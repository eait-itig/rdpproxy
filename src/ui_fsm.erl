%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2023 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(ui_fsm).
-behaviour(gen_statem).

-include_lib("public_key/include/public_key.hrl").

-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/kbd.hrl").
-include_lib("rdp_proto/include/tsud.hrl").
-include_lib("rdp_proto/include/rdpdr.hrl").
-include_lib("rdpproxy/include/PKCS7.hrl").

-include_lib("kernel/include/inet.hrl").

-export([
    start_link/4
    ]).
-export([
    init/1,
    terminate/3,
    code_change/4,
    callback_mode/0
    ]).
-export([
    dead/3,
    loading/3,
    login/3,
    check_login/3,
    check_mfa/3,
    check_smartcard/3,
    check_okta/3,
    check_duo/3,
    check_pin/3,
    duo_choice/3,
    duo_auth/3,
    duo_async/3,
    duo_push_code/3,
    okta_enter_code/3,
    okta_poll/3,
    okta_select/3,
    okta_webauthn/3,
    scard_mfa_select/3,
    scard_mfa_check_pin/3,
    check_shell/3,
    manual_host/3,
    pool_choice/3,
    pool_host_choice/3,
    nms_choice/3,
    alloc_handle/3,
    alloc_waiting/3,
    redir/3,
    editing_host/3,
    check_pin_epw/3,
    offer_epw/3
    ]).

-export([
    register_metrics/0
    ]).

-define(devpgsize, 6).

register_metrics() ->
    prometheus_counter:new([
        {name, rdp_connections_client_os_build_total},
        {labels, [os, build]},
        {help, "Count of RDP connections by OS and build number"}]),
    prometheus_summary:new([
        {name, rdp_connection_ping_milliseconds},
        {labels, [peer]},
        {duration_unit, false},
        {help, "RTT latency measurements"}]),
    prometheus_summary:new([
        {name, rdpproxy_waiting_time_milliseconds},
        {labels, []},
        {duration_unit, false},
        {help, "Time spent on the 'waiting for a backend' screen"}]),
    prometheus_counter:new([
        {name, rdpproxy_wait_aborts_total},
        {labels, []},
        {help, "Users who gave up and disconnected during the wait"}]),
    prometheus_counter:new([
        {name, auth_failures_total},
        {labels, []},
        {help, "Auth failures"}]),
    prometheus_counter:new([
        {name, smartcard_auths_total},
        {labels, []},
        {help, "Successful auths using a smartcard"}]),
    ok.

-spec start_link(Frontend :: rdp_server:server(), Listener :: atom(), lv:instance(), lv:point()) -> {ok, pid()} | {error, term()}.
start_link(Frontend, L, Inst, {W, H}) ->
    gen_statem:start_link(?MODULE, [Frontend, L, Inst, {W, H}], []).

-type duo_choice_push() :: #{device => binary(), method => push | vpush,
    code => binary(), remember_me => boolean()}.
-type duo_choice_call() :: #{device => binary(), method => call,
    remember_me => boolean()}.
-type duo_choice_otp() :: #{device => binary(), method => otp,
    otp => binary(), remember_me => boolean()}.

-type duo_choice() :: duo_choice_push() | duo_choice_call() |
    duo_choice_otp().

-type okta_authenticator() :: #{type => webauthn | totp | push | password | tac,
    name => binary()}.
-type okta_creds() :: #{remember_me => boolean(),
    authenticators_used => [okta_authenticator()],
    pref_username => binary()}.
-type okta_tokens() :: #{access_token => binary(), id_token => binary()}.

-type password_creds() :: #{username => binary(), domain => binary(),
    password => binary(), duo => duo_choice(), okta => okta_creds(),
    tgts => term(), tokens => okta_tokens(),
    scard => #{remember_me => boolean()}}.

-type smartcard_creds() :: #{slot => nist_piv:slot(), pin => binary(),
    tgts => term()}.

-type epw_creds() :: #{slot => nist_piv:slot(), pin => binary(), epw => #{},
    username => binary(), domain => binary(), password => binary(),
    tgts => term()}.

-type creds() :: password_creds() | smartcard_creds() | epw_creds().

-type encrypted_creds() :: map().

-type msec() :: integer().

-type devfilter() :: #{search => string(), mine => boolean(), shared => boolean()}.

-type nms_host_info() :: #{
    hostname => binary(),
    owner => binary(),
    ip => binary(),
    building => binary(),
    room => binary(),
    class => binary(),
    role => binary(),
    desc => binary(),
    last_alloc => integer(),
    group => binary()
    }.

-record(?MODULE, {
    srv :: rdp_server:server(),
    listener :: atom(),
    mref :: reference(),
    res :: lv:point(),
    inst :: lv:instance(),
    peer :: undefined | binary(),
    sty = #{} :: #{atom() => lv:style()},
    pinchars :: lv:buffer(),
    screen :: undefined | lv:scr(),
    widgets = #{} :: #{atom() => lv:object()},
    events = [] :: [lv:event()],
    creds = #{} :: creds(),
    hdl = #{} :: session_ra:handle_state(),
    uinfo :: undefined | session_ra:user_info(),
    cslots :: undefined | [scard_auth_fsm:slot_info()],
    piv :: undefined | pid(),
    scard :: undefined | scard_auth_fsm:fsm(),
    tsudcore :: undefined | #tsud_core{},
    nms :: undefined | pid(),
    hostname :: undefined | binary(),
    duo :: undefined | pid(),
    duoid :: undefined | binary(),
    okta :: undefined | pid(),
    mfa = [] :: [atom()],
    mfa_bypass :: undefined | boolean(),
    errmsg :: undefined | binary(),
    duodevs :: undefined | [map()],
    rmbrchk :: undefined | lv:checkbox(),
    duotx :: undefined | binary(),
    pool :: undefined | atom(),
    allocpid :: undefined | pid(),
    allocmref :: undefined | reference(),
    waitstart :: undefined | msec(),
    rstate :: undefined | atom,
    devmap :: undefined | [{map(), lv:object()}],
    filter = #{} :: devfilter(),
    admin_custom :: undefined | lv:object(),
    admin_custom_label :: undefined | lv_span:span(),
    edit_host :: undefined | nms_host_info(),
    disevt :: undefined | lv:event()
    }).

    % sess :: undefined | session_ra:handle_state(),

    % tsudcore :: undefined | #tsud_core{},

    % pool :: undefined | session_ra:pool(),
    % allocpid :: undefined | pid(),
    % allocmref :: undefined | reference(),
    %
    %
    % d
    %
    % duotx :: undefined | binary(),
    % duoremember = false :: boolean(),
    % waitstart :: undefined | integer(),
    % devs :: undefined | [#{}],
    % devoffset :: undefined | integer(),
    % pools :: undefined | [#{}],
    % pooloffset :: undefined | integer(),
    % duomsg :: undefined | binary()}).

%% @private
init([Srv, L, Inst, {W, H}]) ->
    {Pid, _} = Srv,
    lager:debug("ui_fsm for frontend ~p", [Pid]),
    case process_info(Pid) of
        undefined ->
            {ok, dead, #?MODULE{}};
        _ ->
            ok = gen_fsm:send_event(Pid, {subscribe, self()}),
            MRef = monitor(process, Pid),
            Styles = make_styles(Inst, {W, H}),
            {ok, PinChars} = lv:make_cstring(Inst, <<"0123456789">>),
            {ok, loading, #?MODULE{mref = MRef, srv = Srv, listener = L,
                                   inst = Inst, res = {W,H}, sty = Styles,
                                   pinchars = PinChars}}
    end.

make_styles(Inst, {W, H}) ->
    {R, G, B} = rdpproxy:config([ui, bg_colour], {16#48, 16#20, 16#6c}),
    {ok, Scr} = lv_style:create(Inst, [
        {flex_flow, if (W > H) -> row; true -> column end},
        {flex_align, center, center, center},
        {bg_color, lv_color:make(R, G, B)}
        ]),

    {ok, Flex} = lv_style:create(Inst, [
        {flex_flow, column},
        {flex_align, if (W > H) -> center; true -> start end,
                     start, if (W > H) -> start; true -> center end},
        {bg_opa, 0},
        {border_opa, 0}
        ]),

    {ok, XFlex} = lv_style:create(Inst, [
        {flex_flow, column},
        {flex_align, if (W > H) -> start; true -> center end,
                     start, start},
        {bg_opa, 0},
        {border_opa, 0}
        ]),

    {ok, Row} = lv_style:create(Inst, [
        {flex_flow, row},
        {flex_align, start, center, center},
        {bg_opa, 0},
        {border_opa, 0},
        {pad_all, 0},
        {width, {percent, 100}},
        {height, content}
        ]),

    {ok, Group} = lv_style:create(Inst, [
        {bg_opa, 0.7},
        {border_opa, 0},
        {width, {percent, 100}},
        {height, content}
        ]),

    {ok, Divider} = lv_style:create(Inst, [
        {border_side, [left]},
        {border_color, lv_color:palette(black)},
        {border_opa, 0.5},
        {pad_left, 10},
        {pad_top, 0},
        {pad_bottom, 0},
        {radius, 0}
        ]),

    {ok, Title} = lv_style:create(Inst, [
        {text_font, {"roboto", bold, 32}},
        {text_color, lv_color:palette(white)}
        ]),

    {ok, VCode} = lv_style:create(Inst, [
        {text_font, {"source code pro", bold, 18}},
        {bg_opa, 0.9},
        {bg_color, lv_color:palette(white)},
        {text_color, lv_color:palette(black)},
        {pad_left, 30},
        {pad_right, 30},
        {pad_top, 20},
        {pad_bottom, 20},
        {radius, 5}
    ]),

    {ok, Subtitle} = lv_style:create(Inst, [
        {text_font, {"roboto", regular, 20}},
        {text_color, lv_color:palette(white)}
        ]),

    {ok, Instruction} = lv_style:create(Inst, [
        {text_font, {"montserrat", regular, 16}},
        {text_color, lv_color:palette(white)}
        ]),

    {ok, ItemTitle} = lv_style:create(Inst, [
        {text_font, {"roboto", bold, 16}},
        {text_decor, [underline]}
        ]),

    {ok, ItemTitleFaded} = lv_style:create(Inst, [
        {text_font, {"roboto", bold, 16}},
        {text_decor, [underline]},
        {text_opa, 0.8}
        ]),

    {ok, Role} = lv_style:create(Inst, [
        {text_opa, 0.7}
        ]),

    {ok, Matrix} = lv_style:create(Inst, [
        {pad_all, 6},
        {pad_row, 6},
        {pad_column, 6}
    ]),

    {ok, MatrixItem} = lv_style:create(Inst, [
        {bg_opa, 1.0},
        {bg_color, lv_color:make(16#f3f4f6)},
        {radius, 8},
        {border_color, lv_color:make(16#d1d5db)},
        {border_width, 1},
        {text_color, lv_color:make(16#111827)}
    ]),

    {ok, MatrixChItem} = lv_style:create(Inst, [
        {bg_color, lv_color:make(16#6366f1)},
        {text_color, lv_color:palette(white)},
        {outline_color, lv_color:make(16#6366f1)},
        {outline_width, 3},
        {outline_pad, 2},
        {outline_opa, 0.8}
    ]),

    #{screen => Scr, flex => Flex, group => Group, group_divider => Divider,
      row => Row, title => Title, subtitle => Subtitle,
      instruction => Instruction, item_title => ItemTitle,
      item_title_faded => ItemTitleFaded, role => Role, xflex => XFlex,
      vcode => VCode, matrix => Matrix, matrix_item => MatrixItem,
      matrix_item_checked => MatrixChItem}.

%% @private
callback_mode() -> [state_functions, state_enter].

%% @private
terminate(Reason, State, S0 = #?MODULE{scard = SCard}) when not (SCard =:= undefined) ->
    scard_auth_fsm:stop(SCard),
    terminate(Reason, State, S0#?MODULE{scard = undefined});
terminate(Reason, State, S0 = #?MODULE{okta = Okta}) when not (Okta =:= undefined) ->
    okta:stop(Okta),
    terminate(Reason, State, S0#?MODULE{okta = undefined});
terminate(Reason, State, S0 = #?MODULE{duo = Duo}) when not (Duo =:= undefined) ->
    duo:stop(Duo),
    terminate(Reason, State, S0#?MODULE{duo = undefined});
terminate(Reason, State, S0 = #?MODULE{nms = Nms}) when not (Nms =:= undefined) ->
    nms:stop(Nms),
    terminate(Reason, State, S0#?MODULE{nms = undefined});
terminate(Reason, State, #?MODULE{}) ->
    lager:debug("ui_fsm dying from state ~s due to ~999p", [State, Reason]),
    ok.

%% @private
code_change(_OldVsn, OldState, S0, _Extra) ->
    {ok, OldState, S0}.

do_ping_annotate(#?MODULE{srv = F = {FPid, _}}) ->
    AvgPing = case rdp_server:get_pings(F) of
        {ok, Pings} when length(Pings) > 0 ->
            {Sum, Count} = lists:foldl(fun (P, {Su, C}) -> {Su + P, C + 1} end,
                {0, 0}, Pings),
            Sum / Count;
        _ ->
            unknown
    end,
    case AvgPing of
        unknown -> ok;
        _ ->
            {PeerIp, _PeerPort} = rdp_server:get_peer(F),
            {A,B,_C,_D} = PeerIp,
            PeerIpStr = iolist_to_binary([inet:ntoa({A,B,0,0}), "/16"]),
            prometheus_summary:observe(rdp_connection_ping_milliseconds,
                [PeerIpStr], AvgPing),
            prometheus_summary:observe(rdp_connection_ping_milliseconds,
                [<<"0.0.0.0/0">>], AvgPing)
    end,
    conn_ra:annotate(FPid, #{avg_ping => AvgPing}).

get_msg(Name, #?MODULE{creds = #{username := U}}) ->
    Msg0 = rdpproxy:config([ui, Name]),
    Msg1 = binary:replace(Msg0, [<<"%USER%">>], U, [global]),
    Msg2 = binary:replace(Msg1, [<<"%HELPDESK%">>],
        rdpproxy:config([ui, helpdesk]), [global]),
    Msg2;
get_msg(Name, #?MODULE{}) ->
    Msg0 = rdpproxy:config([ui, Name]),
    Msg1 = binary:replace(Msg0, [<<"%HELPDESK%">>],
        rdpproxy:config([ui, helpdesk]), [global]),
    Msg1.

make_screen(#?MODULE{inst = Inst, res = {W, H}, sty = Sty}) ->
    #{flex := FlexStyle, screen := ScreenStyle} = Sty,
    {ok, Screen} = lv_scr:create(Inst),
    ok = lv_obj:add_style(Screen, ScreenStyle),

    {ok, Logo} = lv_img:create(Screen),
    ok = lv_img:set_src(Logo,
        rdp_lvgl_server:find_image_path(rdpproxy,
            rdpproxy:config([ui, logo], "uq-logo.png"))),
    {ok, {_LogoW, LogoH}} = lv_obj:get_size(Logo),

    {ok, Flex} = lv_obj:create(Inst, Screen),
    ok = lv_obj:add_style(Flex, FlexStyle),

    if
        (W > H) ->
            FlexW = if (0.2 * W < 500) -> 500; true -> {percent, 20} end,
            ok = lv_obj:set_size(Flex, {FlexW, {percent, 100}});
        true ->
            FlexH = H - LogoH - 50,
            ok = lv_obj:set_size(Flex, {{percent, 80}, FlexH})
    end,
    {Screen, Flex}.

make_wide_screen(#?MODULE{inst = Inst, res = {W, H}, sty = Sty}) ->
    #{flex := FlexStyle, screen := ScreenStyle} = Sty,
    {ok, Screen} = lv_scr:create(Inst),
    ok = lv_obj:add_style(Screen, ScreenStyle),

    {ok, Logo} = lv_img:create(Screen),
    ok = lv_img:set_src(Logo,
        rdp_lvgl_server:find_image_path(rdpproxy,
            rdpproxy:config([ui, logo], "uq-logo.png"))),
    {ok, {_LogoW, LogoH}} = lv_obj:get_size(Logo),

    {ok, Flex} = lv_obj:create(Inst, Screen),
    ok = lv_obj:add_style(Flex, FlexStyle),

    if
        (W > H) ->
            FlexW = if (0.6 * W < 600) -> 600; true -> {percent, 60} end,
            ok = lv_obj:set_size(Flex, {FlexW, {percent, 100}});
        true ->
            FlexH = H - LogoH - 50,
            FlexW = if (0.8 * W < 600) -> 600; true -> {percent, 80} end,
            ok = lv_obj:set_size(Flex, {FlexW, FlexH})
    end,
    {Screen, Flex}.

make_waiting_screen(Text, #?MODULE{inst = Inst, sty = Sty}) ->
    #{screen := ScreenStyle, instruction := InstrStyle} = Sty,
    {ok, Screen} = lv_scr:create(Inst),
    ok = lv_obj:add_style(Screen, ScreenStyle),
    {ok, Spinner} = lv_spinner:create(Screen, 1000, 90),
    ok = lv_obj:set_size(Spinner, {100, 100}),
    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),
    {ok, Lbl} = lv_label:create(Screen),
    ok = lv_label:set_text(Lbl, Text),
    ok = lv_obj:add_style(Lbl, InstrStyle),
    Screen.

make_group(TopLevel, Symbol, #?MODULE{inst = Inst, sty = Sty}) ->
    #{xflex := FlexStyle, group := GroupStyle, group_divider := DivStyle} = Sty,

    {ok, Outer} = lv_obj:create(Inst, TopLevel),
    ok = lv_obj:add_style(Outer, GroupStyle),
    ok = lv_obj:set_scrollbar_mode(Outer, off),
    ok = lv_obj:clear_flag(Outer, [scrollable]),

    {ok, Sym} = lv_label:create(Outer),
    ok = lv_obj:set_style_text_font(Sym, {"lineawesome", regular, 20}),
    ok = lv_label:set_text(Sym, unicode:characters_to_binary([Symbol], utf8)),
    ok = lv_obj:align(Sym, left_mid),

    {ok, InnerFlex} = lv_obj:create(Inst, Outer),
    ok = lv_obj:add_style(InnerFlex, FlexStyle),
    ok = lv_obj:add_style(InnerFlex, DivStyle),
    ok = lv_obj:set_size(InnerFlex, {{percent, 95}, content}),
    ok = lv_obj:align(InnerFlex, top_left, {30, 0}),
    ok = lv_obj:set_scroll_dir(InnerFlex, [vertical]),

    InnerFlex.

%% @private
dead(enter, _PrevState, #?MODULE{srv = undefined}) ->
    {keep_state_and_data, [{state_timeout, 0, die}]};
dead(enter, _PrevState, #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {keep_state_and_data, [{state_timeout, 1000, die}]};
dead(state_timeout, die, S0 = #?MODULE{}) ->
    {stop, normal, S0}.

%% @private
loading(enter, _PrevState, S0 = #?MODULE{inst = Inst}) ->
    Screen = make_waiting_screen("Please wait...", S0),
    {ok, TopLayer} = lv_disp:get_layer_top(Inst),

    {ok, DisBtn} = lv_btn:create(TopLayer),
    {ok, DisBtnLbl} = lv_label:create(DisBtn),
    ok = lv_label:set_text(DisBtnLbl, "Disconnect"),
    ok = lv_obj:set_size(DisBtn, {content, 30}),
    ok = lv_obj:align(DisBtn, top_right, {-20, 20}),

    {ok, DisEvt, _} = lv_event:setup(DisBtn, short_clicked, disconnect),

    {keep_state, S0#?MODULE{screen = Screen, disevt = DisEvt},
        [{state_timeout, 500, check}]};
loading(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
loading(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
loading(state_timeout, check, S0 = #?MODULE{srv = Srv, listener = L}) ->
    {FPid, _} = Srv,
    {PeerIp, _PeerPort} = rdp_server:get_peer(Srv),
    PeerIpBin = list_to_binary(inet:ntoa(PeerIp)),

    Caps = rdp_server:get_caps(Srv),
    GeneralCap = lists:keyfind(ts_cap_general, 1, Caps),

    Tsuds = rdp_server:get_tsuds(Srv),
    TsudCore = lists:keyfind(tsud_core, 1, Tsuds),
    #tsud_net{channels = Chans} = lists:keyfind(tsud_net, 1, Tsuds),
    ChanNames = [Name || #tsud_net_channel{name = Name} <- Chans],

    [OSType, OSSubType] = GeneralCap#ts_cap_general.os,
    OS = iolist_to_binary(io_lib:format("~p/~p", [OSType, OSSubType])),
    prometheus_counter:inc(rdp_connections_client_os_build_total,
        [OS, TsudCore#tsud_core.client_build]),

    TSInfo = rdp_server:get_ts_info(Srv),
    #ts_info{timezone = Timezone, workdir = WorkDir} = TSInfo,

    ClientFp = crypto:hash(sha256, [
        term_to_binary(PeerIp),
        term_to_binary(GeneralCap#ts_cap_general.os),
        term_to_binary(TsudCore#tsud_core.version),
        term_to_binary(TsudCore#tsud_core.client_build),
        term_to_binary(TsudCore#tsud_core.client_name),
        term_to_binary(TsudCore#tsud_core.capabilities),
        term_to_binary(TsudCore#tsud_core.prodid),
        term_to_binary(ChanNames),
        term_to_binary(Timezone),
        term_to_binary(WorkDir)
        ]),
    DuoId = base64:encode(ClientFp),

    lager:debug("peer = ~p, duoid = ~p", [PeerIp, DuoId]),

    S1 = S0#?MODULE{tsudcore = TsudCore, duoid = DuoId,
                    peer = PeerIpBin},

    Methods = rdpproxy:config([mfa, methods], [duo]),
    S2 = case lists:member(duo, Methods) of
        true ->
            {ok, Duo} = duo:start_link(),
            S1#?MODULE{duo = Duo, mfa = Methods};
        false ->
            S1#?MODULE{mfa = Methods}
    end,
    S3 = case lists:member(okta, Methods) of
        true ->
            {ok, Okta} = okta:start_link(),
            S2#?MODULE{okta = Okta};
        false ->
            S2
    end,

    Mode = rdpproxy:config([frontend, L, mode], pool),
    S4 = case Mode of
        nms_choice ->
            {ok, Nms} = nms:start_link(),
            S3#?MODULE{nms = Nms};
        _ ->
            S3
    end,

    {_Autologon, U, _D, P} = rdp_server:get_autologon(Srv),
    Creds0 = case U of
        <<>> -> #{};
        _ ->
            {Domain, Username} = split_domain(U, S0),
            #{username => Username, domain => Domain}
    end,
    Creds1 = case P of
        <<>> -> Creds0;
        _ -> Creds0#{password => P}
    end,
    S5 = S4#?MODULE{creds = encrypt_creds(Creds1)},

    {ok, SCard} = scard_auth_fsm:start_link(Srv, self()),

    S6 = receive
        {scard_ready, SCard} ->
            {ok, CardInfo} = scard_auth_fsm:list_cards(SCard),
            [FirstCard | _] = CardInfo,
            conn_ra:annotate(FPid, #{scard => FirstCard}),
            {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
            S5#?MODULE{cslots = Slots, scard = SCard}
    after 2000 ->
        S5#?MODULE{scard = SCard}
    end,

    case rdp_server:get_dvchan_pid(Srv, rdpewa_fsm) of
        {ok, Pid} when is_pid(Pid) ->
            case rdpewa_fsm:list_auths(Pid) of
                {ok, Auths} ->
                    lager:debug("rdpewa authenticators = ~p", [Auths]);
                Else ->
                    lager:debug("failed to get rdpewa authenticators: ~p", [Else])
            end;
        _ ->
            lager:debug("rdpewa not available")
    end,

    case Creds1 of
        #{username := _, password := _} ->
            {next_state, check_login, S6};
        _ ->
            {next_state, login, S6}
    end.

%% @private
login(enter, _PrevState, S0 = #?MODULE{inst = Inst, sty = Sty, creds = Creds,
                                       cslots = CSlots, scard = SCard}) ->
    #{title := TitleStyle, subtitle := SubtitleStyle,
      instruction := InstrStyle, group := GroupStyle} = Sty,
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, rdpproxy:config([ui, title_login])),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Subtitle} = lv_span:new_span(Text),
    ok = lv_span:set_text(Subtitle, [$\n, rdpproxy:config([ui, subtitle_login])]),
    ok = lv_span:set_style(Subtitle, SubtitleStyle),

    {ok, Instr} = lv_label:create(Flex),
    ok = lv_label:set_text(Instr, [rdpproxy:config([ui, instruction_login])]),
    ok = lv_obj:add_style(Instr, InstrStyle),

    S1 = case S0 of
        #?MODULE{errmsg = undefined} -> S0;
        #?MODULE{errmsg = ErrMsg} ->
            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, ErrMsg),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            S0#?MODULE{errmsg = undefined}
    end,

    UPwFlex = make_group(Flex, 16#f2c2, S0),

    {ok, UserText} = lv_textarea:create(UPwFlex),
    ok = lv_textarea:set_one_line(UserText, true),
    ok = lv_textarea:set_text_selection(UserText, true),
    ok = lv_textarea:set_placeholder_text(UserText, "Username"),
    ok = lv_group:add_obj(InpGroup, UserText),

    {ok, PwText} = lv_textarea:create(UPwFlex),
    ok = lv_textarea:set_one_line(PwText, true),
    ok = lv_textarea:set_password_mode(PwText, true),
    ok = lv_textarea:set_text_selection(PwText, true),
    ok = lv_textarea:set_placeholder_text(PwText, "Password"),
    ok = lv_group:add_obj(InpGroup, PwText),

    {ok, Btn} = lv_btn:create(UPwFlex),
    {ok, BtnLbl} = lv_label:create(Btn),
    ok = lv_label:set_text(BtnLbl, "Login"),

    {ok, BtnEvent, _} = lv_event:setup(Btn, short_clicked, {login, UserText, PwText}),
    {ok, UAcEvent, _} = lv_event:setup(UserText, ready, {focus, PwText}),
    {ok, AcEvent, _} = lv_event:setup(PwText, ready, {wait_release,
        {login, UserText, PwText}}),

    Evts0 = [BtnEvent, UAcEvent, AcEvent],
    S2 = S1#?MODULE{screen = Screen, events = Evts0,
                    widgets = #{flex => Flex, inp => InpGroup}},
    S3 = case CSlots of
        undefined -> S2;
        [] -> S2;
        _ -> {keep_state, SS} = login(info, {scard_ready, SCard}, S2), SS
    end,

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    case Creds of
        #{username := Username} ->
            ok = lv_textarea:set_text(UserText, Username),
            ok = lv_group:focus_obj(PwText);
        _ ->
            ok = lv_group:focus_obj(UserText)
    end,

    {keep_state, S3};

login(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard, srv = {FPid,_},
                                                sty = Sty, inst = Inst}) ->
    {ok, AllCards = [FirstCard | _]} = scard_auth_fsm:list_cards(SCard),
    conn_ra:annotate(FPid, #{scard => FirstCard}),

    {ok, CSlots} = scard_auth_fsm:list_valid_slots(SCard),
    S1 = S0#?MODULE{cslots = CSlots},

    #?MODULE{srv = {FPid, _}, events = Evts0, widgets = Widgets} = S0,
    #{flex := Flex, inp := InpGroup} = Widgets,
    #{item_title := ItemTitleStyle, row := RowStyle, role := RoleStyle} = Sty,

    Evts1 = lists:foldl(fun (#{slots := CSIs}, CAcc) ->
        lists:foldl(fun
            (SI = #{card_id := CID,
                    pubkey := PubKey = {#'ECPoint'{}, {namedCurve, _}}}, SAcc) ->
                case scard_saved_pw_ra:get_password(PubKey) of
                    {ok, EPW = #{username := UPN}} ->
                        CardFlex = make_group(Flex, 16#f0a3, S0),

                        {ok, CardInfo} = scard_auth_fsm:get_card(SCard, CID),
                        CardTitle = case CardInfo of
                            #{yk_serial := Serial, yk_version := {Maj, _, _}} ->
                                [<<"YubiKey ">>, integer_to_binary(Maj),
                                 <<"   #">>, integer_to_binary(Serial)];
                            #{reader := Rdr} ->
                                [Rdr]
                        end,

                        {ok, RdrLbl} = lv_label:create(CardFlex),
                        ok = lv_label:set_text(RdrLbl, UPN),
                        ok = lv_obj:add_style(RdrLbl, ItemTitleStyle),

                        {ok, UserLbl} = lv_label:create(CardFlex),
                        ok = lv_obj:add_style(UserLbl, RoleStyle),
                        ok = lv_label:set_text(UserLbl, CardTitle),
                        ok = lv_obj:add_flag(UserLbl, ignore_layout),
                        ok = lv_obj:align(UserLbl, top_right),

                        {ok, Row} = lv_obj:create(Inst, CardFlex),
                        ok = lv_obj:add_style(Row, RowStyle),

                        {ok, PinText} = lv_textarea:create(Row),
                        ok = lv_textarea:set_one_line(PinText, true),
                        ok = lv_textarea:set_text_selection(PinText, true),
                        ok = lv_textarea:set_placeholder_text(PinText, "PIN"),
                        #?MODULE{pinchars = PinChars} = S0,
                        ok = lv_textarea:set_accepted_chars(PinText, PinChars),
                        ok = lv_textarea:set_password_mode(PinText, true),
                        ok = lv_group:add_obj(InpGroup, PinText),

                        {ok, CardBtn} = lv_btn:create(Row),
                        {ok, CardBtnLbl} = lv_label:create(CardBtn),
                        ok = lv_label:set_text(CardBtnLbl, "Login"),

                        {ok, YkBtnEvent, _} = lv_event:setup(CardBtn, short_clicked,
                            {login_epw, SI, PinText, EPW}),
                        {ok, YkAcEvent, _} = lv_event:setup(PinText, ready,
                            {wait_release,
                                {login_epw, SI, PinText, EPW}}),

                        [YkBtnEvent, YkAcEvent | SAcc];
                    _Err ->
                        SAcc
                end;
            (_SI, SAcc) ->
                SAcc
        end, CAcc, CSIs)
    end, Evts0, AllCards),
    Evts2 = lists:foldl(fun
        (#{slot_id := piv_key_mgmt}, Acc) ->
            Acc;
        (SI = #{card_id := CID, upn := UPNs}, Acc) ->
            CardFlex = make_group(Flex, 16#f084, S0),

            [FirstUPN | RestUPNs] = UPNs,

            {ok, CardInfo} = scard_auth_fsm:get_card(SCard, CID),
            CardTitle = case CardInfo of
                #{yk_serial := Serial, yk_version := {Maj, _, _}} ->
                    [<<"YubiKey ">>, integer_to_binary(Maj), <<"   #">>,
                     integer_to_binary(Serial)];
                #{reader := Rdr} ->
                    [Rdr]
            end,

            {ok, RdrLbl} = lv_label:create(CardFlex),
            ok = lv_label:set_text(RdrLbl, FirstUPN),
            ok = lv_obj:add_style(RdrLbl, ItemTitleStyle),

            {ok, UserLbl} = lv_label:create(CardFlex),
            ok = lv_obj:add_style(UserLbl, RoleStyle),
            ok = lv_label:set_text(UserLbl, CardTitle),
            ok = lv_obj:add_flag(UserLbl, ignore_layout),
            ok = lv_obj:align(UserLbl, top_right),

            case RestUPNs of
                [_|_] ->
                    {ok, OtherNamesLbl} = lv_label:create(CardFlex),
                    ok = lv_label:set_text(OtherNamesLbl, ["  ",
                        lists:join(<<"\n  ">>, RestUPNs)]);
                _ ->
                    ok
            end,

            {ok, Row} = lv_obj:create(Inst, CardFlex),
            ok = lv_obj:add_style(Row, RowStyle),

            {ok, PinText} = lv_textarea:create(Row),
            ok = lv_textarea:set_one_line(PinText, true),
            ok = lv_textarea:set_text_selection(PinText, true),
            ok = lv_textarea:set_placeholder_text(PinText, "PIN"),
            #?MODULE{pinchars = PinChars} = S0,
            ok = lv_textarea:set_accepted_chars(PinText, PinChars),
            ok = lv_textarea:set_password_mode(PinText, true),
            ok = lv_group:add_obj(InpGroup, PinText),

            {ok, CardBtn} = lv_btn:create(Row),
            {ok, CardBtnLbl} = lv_label:create(CardBtn),
            ok = lv_label:set_text(CardBtnLbl, "Login"),

            {ok, YkBtnEvent, _} = lv_event:setup(CardBtn, short_clicked,
                {login_pin, SI, PinText}),
            {ok, YkAcEvent, _} = lv_event:setup(PinText, ready,
                {wait_release, {login_pin, SI, PinText}}),

            [YkBtnEvent, YkAcEvent | Acc];
        (_SI, Acc) ->
            Acc
    end, Evts1, CSlots),
    S2 = S1#?MODULE{events = Evts2},
    {keep_state, S2};
login(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};

login(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

login(info, {Ref, {wait_release, Evt}}, S0 = #?MODULE{inst = Inst}) ->
    ok = lv_indev:wait_release(Inst, keyboard),
    login(info, {Ref, Evt}, S0);

login(info, {_, {focus, Field}}, S0 = #?MODULE{inst = Inst}) ->
    ok = lv_indev:wait_release(Inst, keyboard),
    ok = lv_group:focus_obj(Field),
    {keep_state, S0};

login(info, {_, {login, UserText, PwText}}, S0 = #?MODULE{}) ->
    {ok, UserDomain} = lv_textarea:get_text(UserText),
    {ok, Password} = lv_textarea:get_text(PwText),
    {Domain, Username} = split_domain(UserDomain, S0),
    C0 = #{username => Username, password => Password, domain => Domain},
    S1 = S0#?MODULE{creds = encrypt_creds(C0)},
    {next_state, check_login, S1};

login(info, {_, {login_pin, SI, PinText}}, S0 = #?MODULE{}) ->
    #{card_id := CardId, slot_id := SlotId} = SI,
    {ok, Pin} = lv_textarea:get_text(PinText),
    S1 = S0#?MODULE{creds = encrypt_creds(#{slot_info => SI,
                                            card_id => CardId,
                                            slot_id => SlotId,
                                            pin => Pin})},
    {next_state, check_pin, S1};

login(info, {_, {login_epw, SI, PinText, EPW}}, S0 = #?MODULE{}) ->
    #{card_id := CardId, slot_id := SlotId} = SI,
    {ok, Pin} = lv_textarea:get_text(PinText),
    S1 = S0#?MODULE{creds = encrypt_creds(#{slot_info => SI,
                                            card_id => CardId,
                                            slot_id => SlotId,
                                            pin => Pin,
                                            epw => EPW})},
    {next_state, check_pin_epw, S1}.

normalise_user_domain(UserOrUPN, #?MODULE{listener = L}) ->
    [DefaultDomain | _] = rdpproxy:config([frontend, L, domains], [<<".">>]),
    case string:split(UserOrUPN, "@") of
        [U, D] -> {string:lowercase(unicode:characters_to_binary(U, utf8)),
                   string:uppercase(unicode:characters_to_binary(D, utf8))};
        [U] -> {string:lowercase(unicode:characters_to_binary(U, utf8)),
                string:uppercase(unicode:characters_to_binary(DefaultDomain, utf8))}
    end.

check_pin(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying PIN...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
check_pin(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_pin(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_pin(state_timeout, check, S0 = #?MODULE{creds = #{pin := <<>>}}) ->
    {next_state, login, S0#?MODULE{errmsg = <<"PIN required">>}};
check_pin(state_timeout, check, S0 = #?MODULE{creds = Creds0,
                                              scard = SCard,
                                              listener = L}) ->
    #{card_id := CardId, slot_id := SlotId, slot_info := SI, pin := PIN} =
        decrypt_creds(Creds0),
    #{card_id := CardId, slot_id := SlotId} = SI,

    #{upn := [UPN | _]} = SI,
    [DomainRaw | _] = rdpproxy:config([frontend, L, domains], [<<".">>]),
    Domain = string:uppercase(unicode:characters_to_binary(DomainRaw, utf8)),
    {Username, _CertDomain} = normalise_user_domain(UPN, S0),

    Creds1 = Creds0#{username => Username, domain => Domain},
    UInfo = #{user => Username, groups => []},

    Screen = make_waiting_screen("Challenging smartcard key...\n"
        "(Touch may be required)", S0),
    S1 = S0#?MODULE{creds = Creds1, uinfo = UInfo, screen = Screen},

    R = scard_auth_fsm:transaction(SCard, CardId, [
        {verify_pin, PIN}, {challenge, SlotId} ]),
    case R of
        {ok, _} ->
            prometheus_counter:inc(smartcard_auths_total),
            #?MODULE{srv = {FPid, _}} = S1,
            conn_ra:annotate(FPid, #{
                session => #{
                    user => Username,
                    domain => Domain,
                    ip => undefined
                    },
                smartcard_used => maps:remove(dn,
                    maps:remove(pubkey, maps:remove(cert, SI)))
                }),
            {next_state, check_mfa, S1};
        {error, verify_pin, verification_failed} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = <<"Smartcard is invalid or faulty ",
                "(CAK verification failed)">>,
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, verify_pin, {bad_auth, Attempts}} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Incorrect Smartcard PIN, ~B attempts left",
                [Attempts])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, challenge, verification_failed} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = <<"Invalid Smartcard (signature "
                "verification failure)">>,
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, verify_pin, Why} ->
            lager:debug("verify pin err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard during PIN verification:\n"
                "~p", [Why])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, challenge, Why} ->
            lager:debug("challenge err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard while signing challenge:\n"
                "~p", [Why])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, Why} ->
            lager:debug("transaction err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard:\n"
                "~p", [Why])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}}
    end;
check_pin(_, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]}.

check_pin_epw(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying PIN...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
check_pin_epw(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_pin_epw(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_pin_epw(state_timeout, check, S0 = #?MODULE{creds = #{pin := <<>>}}) ->
    {next_state, login, S0#?MODULE{errmsg = <<"PIN required">>}};
check_pin_epw(state_timeout, check, S0 = #?MODULE{creds = Creds0,
                                                  scard = SCard}) ->
    Creds1 = decrypt_creds(Creds0),
    #{card_id := CardId, slot_id := SlotId, slot_info := SI, pin := PIN,
      epw := EPW} = Creds1,
    #{card_id := CardId, slot_id := SlotId} = SI,

    #{username := UPN} = EPW,
    {Username, Domain} = normalise_user_domain(UPN, S0),

    Creds2 = Creds1#{username => Username,
                     domain => Domain},
    UInfo = #{user => Username, groups => []},

    Screen = make_waiting_screen("Decrypting credentials...\n"
        "(Touch may be required)", S0),
    S1 = S0#?MODULE{creds = encrypt_creds(Creds1), uinfo = UInfo,
                    screen = Screen},

    R = scard_auth_fsm:transaction(SCard, CardId, [
        {verify_pin, PIN}, {decrypt_epw, SlotId, EPW} ]),
    case R of
        {ok, [ok, {ok, Pw}]} ->
            prometheus_counter:inc(smartcard_auths_total),
            #?MODULE{srv = {FPid, _}} = S0,
            conn_ra:annotate(FPid, #{
                session => #{
                    user => Username,
                    domain => Domain,
                    ip => undefined
                    },
                smartcard_used => maps:remove(dn,
                    maps:remove(pubkey, maps:remove(cert, SI)))
                }),
            Creds3 = Creds2#{password => Pw},
            S2 = S1#?MODULE{creds = encrypt_creds(Creds3)},
            {next_state, check_login, S2};
        {error, verify_pin, verification_failed} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = <<"Smartcard is invalid or faulty ",
                "(CAK verification failed)">>,
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, verify_pin, {bad_auth, Attempts}} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Incorrect Smartcard PIN, ~B attempts left",
                [Attempts])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, verify_pin, Why} ->
            lager:debug("verify pin err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard during PIN verification:\n"
                "~p", [Why])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, decrypt_epw, Why} ->
            lager:debug("decrypt_epw err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard while decrypting creds:\n"
                "~p", [Why])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
        {error, Why} ->
            lager:debug("transaction err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard:\n"
                "~p", [Why])),
            {next_state, login, S0#?MODULE{errmsg = ErrMsg}}
    end;
check_pin_epw(_, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]}.

check_login(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying login details...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
check_login(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_login(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
check_login(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_login(state_timeout, check, S0 = #?MODULE{creds = #{username := <<>>}}) ->
    {next_state, login, S0#?MODULE{errmsg = <<"Username and password required">>}};
check_login(state_timeout, check, S0 = #?MODULE{creds = #{password := <<>>}}) ->
    {next_state, login, S0#?MODULE{errmsg = <<"Username and password required">>}};
check_login(state_timeout, check, S0 = #?MODULE{creds = ECreds, srv = Srv}) ->
    Creds0 = decrypt_creds(ECreds),
    #{username := Username, password := _, domain := Domain} = Creds0,
    {FPid, _} = Srv,
    case krb_auth:authenticate(Creds0) of
        {true, UInfo, Tgts} ->
            lager:debug("auth for ~s succeeded!", [Username]),
            conn_ra:annotate(FPid, #{
                session => #{ip => undefined, password => snip,
                    tgts => snip, user => Username, domain => Domain}
                }),
            S1 = S0#?MODULE{creds = encrypt_creds(Creds0#{tgts => Tgts}),
                            uinfo = UInfo},
            {next_state, check_mfa, S1};

        false ->
            lager:debug("auth for ~s failed", [Username]),
            prometheus_counter:inc(auth_failures_total),
            {next_state, login, S0#?MODULE{
                errmsg = <<"Invalid username or password.">>}}
    end;
check_login(_, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]}.

split_domain(UserDomain, #?MODULE{listener = L}) ->
    [DefaultDomain | _] = ValidDomains = rdpproxy:config(
        [frontend, L, domains], [<<".">>]),
    case binary:split(UserDomain, <<$\\>>) of
        [D, U] -> case lists:member(D, ValidDomains) of
            true -> {D, U};
            false -> {DefaultDomain, U}
        end;
        [U] -> {DefaultDomain, U}
    end.

check_mfa(enter, _PrevState, S0 = #?MODULE{mfa_bypass = undefined}) ->
    Screen = make_waiting_screen("Checking MFA...", S0),
    do_ping_annotate(S0),
    Methods = rdpproxy:config([mfa, methods], [duo]),
    {keep_state, S0#?MODULE{screen = Screen, mfa = Methods},
     [{state_timeout, 100, check_bypass}]};
check_mfa(state_timeout, check_bypass, S0 = #?MODULE{duoid = DuoId, creds = Creds}) ->
    #{username := Username} = Creds,
    case process_acl([mfa, bypass_acl], S0) of
        allow ->
            lager:debug("skipping MFA for ~p due to bypass_acl", [Username]),
            S1 = S0#?MODULE{mfa_bypass = true},
            check_epw(S1);
        deny ->
            case remember_ra:check({DuoId, Username}) of
                true ->
                    lager:debug("skipping MFA for ~p due to remember me", [Username]),
                    S1 = S0#?MODULE{mfa_bypass = true},
                    check_epw(S1);
                false ->
                    S1 = S0#?MODULE{mfa_bypass = false},
                    check_mfa(enter, check_mfa, S1)
            end
    end;
check_mfa(enter, _PrevState, S0 = #?MODULE{mfa = []}) ->
    Screen = make_waiting_screen("Checking MFA...", S0),
    do_ping_annotate(S0),
    lager:error("no mfa methods remaining, bailing"),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, return_to_login}]};
check_mfa(state_timeout, return_to_login, S0 = #?MODULE{errmsg = EM}) ->
    EM1 = case EM of
        undefined -> <<"No MFA methods remaining">>;
        _ -> EM
    end,
    Methods = rdpproxy:config([mfa, methods], [duo]),
    {next_state, login, S0#?MODULE{mfa = Methods, errmsg = EM1}};
check_mfa(enter, _PrevState, S0 = #?MODULE{mfa = [_ | _]}) ->
    Screen = make_waiting_screen("Checking MFA...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, next_method}]};
check_mfa(state_timeout, next_method, S0 = #?MODULE{mfa = [NextMethod | Rest]}) ->
    S1 = S0#?MODULE{mfa = Rest},
    lager:debug("mfa trying method ~p next...", [NextMethod]),
    case NextMethod of
        duo -> {next_state, check_duo, S1};
        smartcard -> {next_state, check_smartcard, S1};
        okta -> {next_state, check_okta, S1}
    end;
check_mfa(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_mfa(_, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]}.

check_duo(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Checking Duo MFA...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, {preauth, 3}}]};
check_duo(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_duo(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_duo(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
check_duo(state_timeout, {preauth, N}, S0 = #?MODULE{creds = Creds, srv = Srv,
                                                duo = Duo, peer = Peer,
                                                duoid = DuoId}) ->
    {FPid, _} = Srv,
    #{username := Username} = Creds,
    Args = #{
        <<"username">> => Username,
        <<"ipaddr">> => Peer,
        <<"trusted_device_token">> => DuoId,
        <<"client_supports_verified_push">> => <<"1">>
    },
    EnrollIsAllow = rdpproxy:config([duo, enroll_is_allow], false),
    Res = duo:preauth(Duo, Args),
    case Res of
        {ok, #{<<"result">> := R}} ->
            conn_ra:annotate(FPid, #{duo_preauth => R});
        _ ->
            ok
    end,
    case Res of
        {ok, #{<<"result">> := <<"enroll">>}} when EnrollIsAllow ->
            lager:debug("duo preauth said enroll for ~p: bypassing", [Username]),
            {next_state, check_mfa, S0};
        {ok, #{<<"result">> := <<"enroll">>}} ->
            S1 = S0#?MODULE{errmsg =
                <<"Duo MFA required but not enrolled.\n"
                  "Visit auth.uq.edu.au in a web browser to set up.">>},
            {next_state, check_mfa, S1};
        {ok, #{<<"result">> := <<"allow">>}} ->
            lager:debug("duo bypass for ~p", [Username]),
            check_epw(S0);
        {ok, #{<<"result">> := <<"auth">>, <<"devices">> := Devs0 = [_Dev1 | _]} = RR} ->
            Devs1 = case RR of
                #{<<"verification_code">> := Code} ->
                    % put the verification code into each device record so if
                    % any have "push" then we can just grab it there in the next
                    % step
                    [D#{<<"verification_code">> => Code} || D <- Devs0];
                _ -> Devs0
            end,
            S1 = S0#?MODULE{duodevs = Devs1},
            lager:debug("sending ~p to duo screen", [Username]),
            {next_state, duo_choice, S1};
        {ok, #{<<"result">> := <<"deny">>, <<"status_msg">> := Msg}} ->
            S1 = S0#?MODULE{errmsg = Msg},
            lager:debug("duo deny for ~p: ~p (id = ~p)", [Username, Msg, DuoId]),
            {next_state, check_mfa, S1};
        {error, {error, timeout}} when (N > 0) ->
            lager:debug("timed out doing duo preauth, trying again"),
            {keep_state_and_data, [{state_timeout, 100, {preauth, N - 1}}]};
        Else ->
            lager:debug("duo preauth else for ~p: ~p (id = ~p)", [Username, Else, DuoId]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Duo MFA:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, check_mfa, S1}
    end.

check_smartcard(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Checking Smartcard MFA...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, check}]};
check_smartcard(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_smartcard(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_smartcard(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
check_smartcard(state_timeout, check,
        S0 = #?MODULE{creds = #{card_id := _, slot_id := _, epw := _}}) ->
    check_epw(S0);
check_smartcard(state_timeout, check,
        S0 = #?MODULE{creds = #{card_id := _, slot_id := _, pin := _}}) ->
    check_epw(S0);
check_smartcard(state_timeout, check, S0 = #?MODULE{cslots = undefined}) ->
    {next_state, check_mfa, S0};
check_smartcard(state_timeout, check, S0 = #?MODULE{cslots = []}) ->
    {next_state, check_mfa, S0};
check_smartcard(state_timeout, check, S0 = #?MODULE{}) ->
    Slots = scard_mfa_slots_for_user(S0),
    case Slots of
        [] ->
            {next_state, check_mfa, S0};
        [_|_] ->
            {next_state, scard_mfa_select, S0}
    end.

scard_mfa_slots_for_user(S0 = #?MODULE{creds = Creds, cslots = Slots}) ->
    #{username := UserOrUPN} = Creds,
    {User, _Domain} = normalise_user_domain(UserOrUPN, S0),
    lists:foldl(fun
        (SI = #{upn := UPNs, card_id := CardId, slot_id := SlotId}, Acc) ->
            HasUPN = lists:any(fun (UPN) ->
                {SlotUser, _SlotDomain} = normalise_user_domain(UPN, S0),
                User =:= SlotUser
            end, UPNs),
            CredsCheck = Creds#{card_id => CardId, slot_id => SlotId},
            SCheck = S0#?MODULE{creds = CredsCheck},
            HasACL = process_acl([smartcard, mfa_acl], SCheck) =:= allow,
            if
                HasUPN ->
                    [#{match => upn, slot => SI} | Acc];
                HasACL ->
                    [#{match => acl, slot => SI} | Acc];
                true ->
                    Acc
            end;
        (_, Acc) ->
            Acc
    end, [], Slots).

scard_mfa_select(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst,
                                                  scard = SCard}) ->
    #{group := GroupStyle, title := TitleStyle, instruction := InstrStyle,
      role := RoleStyle, item_title := ItemTitleStyle,
      row := RowStyle} = Sty,
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, "Smartcard/YubiKey MFA"),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Instr} = lv_span:new_span(Text),
    ok = lv_span:set_text(Instr, [$\n, rdpproxy:config([ui, instruction_mfa])]),
    ok = lv_span:set_style(Instr, InstrStyle),

    S1 = case S0 of
        #?MODULE{errmsg = undefined} -> S0;
        #?MODULE{errmsg = ErrMsg} ->
            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, ErrMsg),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            S0#?MODULE{errmsg = undefined}
    end,

    Slots = scard_mfa_slots_for_user(S1),

    Evts0 = lists:foldl(fun
        (#{match := M, slot := SI = #{card_id := CID, upn := UPNs}}, Acc) ->
            CardFlex = make_group(Flex, 16#f084, S0),

            [FirstUPN | RestUPNs] = UPNs,

            {ok, CardInfo} = scard_auth_fsm:get_card(SCard, CID),
            CardTitle = case CardInfo of
                #{yk_serial := Serial, yk_version := {Maj, _, _}} ->
                    [<<"YubiKey ">>, integer_to_binary(Maj), <<" #">>,
                     integer_to_binary(Serial)];
                #{reader := Rdr} ->
                    [Rdr]
            end,

            {ok, RdrLbl} = lv_label:create(CardFlex),
            ok = lv_label:set_text(RdrLbl, FirstUPN),
            ok = lv_obj:add_style(RdrLbl, ItemTitleStyle),

            {ok, UserLbl} = lv_label:create(CardFlex),
            ok = lv_obj:add_style(UserLbl, RoleStyle),
            ok = lv_label:set_text(UserLbl, CardTitle),
            ok = lv_obj:add_flag(UserLbl, ignore_layout),
            ok = lv_obj:align(UserLbl, top_right),

            case RestUPNs of
                [_|_] ->
                    {ok, OtherNamesLbl} = lv_label:create(CardFlex),
                    ok = lv_label:set_text(OtherNamesLbl, ["  ",
                        lists:join(<<"\n  ">>, RestUPNs)]);
                _ ->
                    ok
            end,

            case M of
                acl ->
                    {ok, WhyLbl} = lv_label:create(CardFlex),
                    ok = lv_obj:add_style(WhyLbl, RoleStyle),
                    ok = lv_label:set_text(WhyLbl, "(MFA exception rule)");
                _ -> ok
            end,

            {ok, Row} = lv_obj:create(Inst, CardFlex),
            ok = lv_obj:add_style(Row, RowStyle),

            {ok, PinText} = lv_textarea:create(Row),
            ok = lv_textarea:set_one_line(PinText, true),
            ok = lv_textarea:set_text_selection(PinText, true),
            ok = lv_textarea:set_placeholder_text(PinText, "PIN"),
            #?MODULE{pinchars = PinChars} = S0,
            ok = lv_textarea:set_accepted_chars(PinText, PinChars),
            ok = lv_textarea:set_password_mode(PinText, true),
            ok = lv_group:add_obj(InpGroup, PinText),

            {ok, CardBtn} = lv_btn:create(Row),
            {ok, CardBtnLbl} = lv_label:create(CardBtn),
            ok = lv_label:set_text(CardBtnLbl, "Verify"),

            {ok, YkBtnEvent, _} = lv_event:setup(CardBtn, short_clicked,
                {login_pin, SI, PinText}),
            {ok, YkAcEvent, _} = lv_event:setup(PinText, ready,
                {wait_release, {login_pin, SI, PinText}}),

            [YkBtnEvent, YkAcEvent | Acc];
        (_, Acc) ->
            Acc
    end, [], Slots),

    {ok, CheckOuter} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(CheckOuter, GroupStyle),

    {ok, RememberCheck} = lv_checkbox:create(CheckOuter),
    ok = lv_checkbox:set_text(RememberCheck, "Remember this computer (skip MFA for next 10 hours)"),

    {ok, CancelBtn} = lv_btn:create(Flex),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    CancelText = case S0 of
        #?MODULE{mfa = [NextMethod | _]} ->
            ["Try another method (", string:titlecase(
                atom_to_binary(NextMethod, utf8)), ")"];
        #?MODULE{mfa = []} ->
            ["Cancel"]
    end,
    ok = lv_label:set_text(CancelBtnLbl, CancelText),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),
    Evts1 = [CancelEvt | Evts0],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S1#?MODULE{screen = Screen, events = Evts1,
                            rmbrchk = RememberCheck}};
scard_mfa_select(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
scard_mfa_select(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
scard_mfa_select(info, {Ref, {wait_release, Evt}}, S0 = #?MODULE{inst = Inst}) ->
    ok = lv_indev:wait_release(Inst, keyboard),
    scard_mfa_select(info, {Ref, Evt}, S0);
scard_mfa_select(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {next_state, scard_mfa_select, S0#?MODULE{cslots = Slots}};
scard_mfa_select(info, {_, cancel}, S0 = #?MODULE{creds = Creds0}) ->
    Creds1 = maps:remove(card_id,
        maps:remove(slot_id, maps:remove(slot_info, Creds0))),
    {next_state, check_mfa, S0#?MODULE{creds = Creds1}};
scard_mfa_select(info, {_, {login_pin, SI, PinText}},
                 S0 = #?MODULE{creds = Creds0, rmbrchk = RmbrChk}) ->
    Creds1 = decrypt_creds(Creds0),
    #{card_id := CardId, slot_id := SlotId} = SI,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    SCC = #{remember_me => RememberMe},
    {ok, Pin} = lv_textarea:get_text(PinText),
    S1 = S0#?MODULE{creds = encrypt_creds(Creds1#{slot_info => SI,
                                                  card_id => CardId,
                                                  slot_id => SlotId,
                                                  pin => Pin,
                                                  scard => SCC})},
    {next_state, scard_mfa_check_pin, S1}.

scard_mfa_check_pin(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying PIN...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
scard_mfa_check_pin(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
scard_mfa_check_pin(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
scard_mfa_check_pin(state_timeout, check, S0 = #?MODULE{creds = #{pin := <<>>}}) ->
    {next_state, scard_mfa_select, S0#?MODULE{errmsg = <<"PIN required">>}};
scard_mfa_check_pin(state_timeout, check,
                    S0 = #?MODULE{creds = Creds0, scard = SCard}) ->
    Creds1 = decrypt_creds(Creds0),
    #{card_id := CardId, slot_id := SlotId, slot_info := SI, pin := PIN,
      username := Username} = Creds1,
    #{card_id := CardId, slot_id := SlotId} = SI,
    SCC = maps:get(scard, Creds0, #{}),
    RememberMe = maps:get(remember_me, SCC, false),
    Screen = make_waiting_screen("Challenging smartcard key...\n"
        "(Touch may be required)", S0),
    S1 = S0#?MODULE{screen = Screen},
    R = scard_auth_fsm:transaction(SCard, CardId, [
        {verify_pin, PIN}, {challenge, SlotId} ]),
    case R of
        {ok, _} ->
            #?MODULE{srv = {FPid, _}} = S1,
            conn_ra:annotate(FPid, #{
                smartcard_used => maps:remove(dn,
                    maps:remove(pubkey, maps:remove(cert, SI)))
                }),
            case RememberMe of
                false -> ok;
                true ->
                    #?MODULE{duoid = DuoId} = S1,
                    ok = remember_ra:remember({DuoId, Username})
            end,
            check_epw(S1);
        {error, verify_pin, verification_failed} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = <<"Smartcard is invalid or faulty ",
                "(CAK verification failed)">>,
            {next_state, scard_mfa_select, S1#?MODULE{errmsg = ErrMsg}};
        {error, verify_pin, {bad_auth, Attempts}} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Incorrect Smartcard PIN, ~B attempts left",
                [Attempts])),
            {next_state, scard_mfa_select, S1#?MODULE{errmsg = ErrMsg}};
        {error, challenge, verification_failed} ->
            prometheus_counter:inc(auth_failures_total),
            ErrMsg = <<"Invalid Smartcard (signature "
                "verification failure)">>,
            {next_state, scard_mfa_select, S1#?MODULE{errmsg = ErrMsg}};
        {error, verify_pin, Why} ->
            lager:debug("verify pin err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard during PIN verification:\n"
                "~p", [Why])),
            {next_state, scard_mfa_select, S1#?MODULE{errmsg = ErrMsg}};
        {error, challenge, Why} ->
            lager:debug("challenge err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard while signing challenge:\n"
                "~p", [Why])),
            {next_state, scard_mfa_select, S1#?MODULE{errmsg = ErrMsg}};
        {error, Why} ->
            lager:debug("transaction err = ~999p", [Why]),
            ErrMsg = iolist_to_binary(io_lib:format(
                "Error communicating with Smartcard:\n"
                "~p", [Why])),
            {next_state, scard_mfa_select, S1#?MODULE{errmsg = ErrMsg}}
    end;
scard_mfa_check_pin(_, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]}.

check_okta(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Checking Okta MFA...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, {begin_auth, 3}}]};
check_okta(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_okta(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_okta(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
check_okta(state_timeout, {begin_auth, N}, S0 = #?MODULE{creds = Creds, srv = Srv,
                                                okta = Okta, peer = Peer,
                                                duoid = DuoId, tsudcore = TsudCore}) ->
    #{username := Username} = Creds,

    Caps = rdp_server:get_caps(Srv),
    GeneralCap = lists:keyfind(ts_cap_general, 1, Caps),
    [OSType, OSSubType] = GeneralCap#ts_cap_general.os,
    [MajVer, MinVer] = TsudCore#tsud_core.version,

    Meta = #{
        login_hint => Username,
        client_ip => Peer,
        os_type => OSType,
        os_subtype => OSSubType,
        os_build => TsudCore#tsud_core.client_build,
        rdp_version => {MajVer, MinVer},
        device_id => binary:part(DuoId, {0,32})
    },
    lager:debug("okta meta = ~p", [Meta]),

    case okta:begin_auth(Okta, Meta) of
        {ok, next_steps, Steps} ->
            okta_next(Steps, S0);
        {warning, Msgs, next_steps, Steps} ->
            lager:debug("okta warnings: ~p", [Msgs]),
            okta_next(Steps, S0);
        {error, Msgs, next_steps, _Steps} ->
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            {next_state, check_mfa, S1};
        {error, {error, timeout}} when (N > 0) ->
            lager:debug("timed out doing okta begin_auth, trying again"),
            {keep_state_and_data, [{state_timeout, 100, {begin_auth, N - 1}}]};
        Else ->
            lager:debug("okta begin_auth else for ~p: ~p (id = ~p)", [Username, Else, DuoId]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, check_mfa, S1}
    end.

okta_add_step(Type, Info, S0 = #?MODULE{creds = Creds0}) when is_map(Info) ->
    O0 = maps:get(okta, Creds0, #{}),
    Steps0 = maps:get(authenticators_used, O0, []),
    Steps1 = [Info#{type => Type} | Steps0],
    O1 = O0#{authenticators_used => Steps1},
    Creds1 = Creds0#{okta => O1},
    S0#?MODULE{creds = Creds1};
okta_add_step(Type, Name, S0) -> okta_add_step(Type, #{name => Name}, S0).

okta_finish(Tokens, S0 = #?MODULE{srv = {FPid,_}, creds = Creds0, duoid = DuoId}) ->
    #{access_token := AT, id_token := IT,
      claims := #{<<"preferred_username">> := PrefUser}} = Tokens,
    Creds1 = decrypt_creds(Creds0),
    O0 = maps:get(okta, Creds1, #{}),
    RememberMe = maps:get(remember_me, O0, false),
    U = maps:get(username, Creds1),
    O1 = O0#{pref_username => PrefUser},
    Creds2 = Creds1#{tokens => #{access_token => AT, id_token => IT},
                     okta => O1},
    Creds3 = encrypt_creds(Creds2),
    S1 = S0#?MODULE{creds = Creds3},
    #{authenticators_used := Steps} = O1,
    lager:debug("okta mfa finished, auths used = ~p", [Steps]),
    conn_ra:annotate(FPid, #{
        okta_authenticators => Steps,
        okta_username => PrefUser
        }),
    case RememberMe of
        false -> ok;
        true -> ok = remember_ra:remember({DuoId, U})
    end,
    check_epw(S1).

okta_next(#{device_challenge_poll := _}, S0 = #?MODULE{okta = Okta}) ->
    lager:debug("cancelling device_challenge_poll"),
    case okta:proceed(Okta, cancel_polling) of
        {ok, next_steps, Steps} ->
            okta_next(Steps, S0);
        {warning, Msgs, next_steps, Steps} ->
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        {error, Msgs, next_steps, _Steps} ->
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            {next_state, check_mfa, S1};
        Else ->
            lager:debug("okta else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, check_mfa, S1}
    end;
okta_next(#{identify := _}, S0 = #?MODULE{okta = Okta, creds = Creds}) ->
    #{username := Username} = Creds,
    lager:debug("identifying as ~p", [Username]),
    case okta:proceed(Okta, identify, #{identifier => Username}) of
        {ok, next_steps, Steps} ->
            okta_next(Steps, S0);
        {ok, finished, Tokens} ->
            lager:debug("okta returned auth finished after identify!?"),
            okta_finish(Tokens, S0);
        {warning, Msgs, next_steps, Steps} ->
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        {error, Msgs, next_steps, _Steps} ->
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            {next_state, check_mfa, S1};
        Else ->
            lager:debug("okta else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, check_mfa, S1}
    end;
okta_next(#{challenge_authenticator := #{authenticator := {password,_,_}}},
          S0 = #?MODULE{okta = Okta, creds = ECreds}) ->
    Creds = decrypt_creds(ECreds),
    #{password := Password} = Creds,
    A = #{credentials => #{passcode => Password}},
    lager:debug("submitting password"),
    case okta:proceed(Okta, challenge_authenticator, A) of
        {ok, next_steps, Steps} ->
            S1 = okta_add_step(password, <<"Password">>, S0),
            okta_next(Steps, S1);
        {ok, finished, Tokens} ->
            S1 = okta_add_step(password, <<"Password">>, S0),
            okta_finish(Tokens, S1);
        {warning, Msgs, next_steps, Steps} ->
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs,
                okta_add_step(password, <<"Password">>, S0)),
            okta_next(Steps, S1);
        {error, Msgs, next_steps, _Steps} ->
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            {next_state, login, S1};
        Else ->
            lager:debug("okta else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, login, S1}
    end;

okta_next(#{challenge_authenticator := #{authenticator := {webauthn, _, _}}},
          S0 = #?MODULE{}) ->
    lager:debug("ready for webauthn"),
    {next_state, okta_webauthn, S0};

okta_next(#{challenge_authenticator := #{properties := Props}}, S0 = #?MODULE{}) ->
    [credentials] = maps:keys(Props),
    #{credentials := {object, #{properties := CredProps}}} = Props,
    [_|_] = maps:keys(CredProps),
    lager:debug("ready for code entry"),
    {next_state, okta_enter_code, S0};

okta_next(#{challenge_poll := _}, S0 = #?MODULE{}) ->
    lager:debug("polling okta"),
    {next_state, okta_poll, S0};

okta_next(#{select_authenticator := _}, S0 = #?MODULE{}) ->
    lager:debug("ready to select authenticator"),
    {next_state, okta_select, S0}.

okta_select(enter, _PrevState, S0 = #?MODULE{okta = Okta, sty = Sty,
                                             inst = Inst, srv = Srv}) ->
    #{row := RowStyle, group := GroupStyle, title := TitleStyle,
      instruction := InstrStyle, item_title := ItemTitleStyle} = Sty,
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, rdpproxy:config([ui, title_mfa])),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Instr} = lv_span:new_span(Text),
    ok = lv_span:set_text(Instr, [$\n, rdpproxy:config([ui, instruction_mfa])]),
    ok = lv_span:set_style(Instr, InstrStyle),

    S1 = case S0 of
        #?MODULE{errmsg = undefined} -> S0;
        #?MODULE{errmsg = ErrMsg} ->
            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, ErrMsg),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            S0#?MODULE{errmsg = undefined}
    end,

    HasWebAuthn = case rdp_server:get_dvchan_pid(Srv, rdpewa_fsm) of
        {ok, Pid} when is_pid(Pid) -> true;
        _ -> false
    end,

    {ok, #{properties := #{authenticator := {choice, _, Options}}}} =
        okta:rinfo(Okta, select_authenticator),

    Evts0 = lists:foldl(fun
        (#{authenticator := {webauthn, _Com, EIs}, label := Label}, Acc0) ->
            DevNames = lists:uniq([D || #{device_name := D} <- EIs]),
            DevName0 = iolist_to_binary(lists:join(<<"\n">>, DevNames)),

            DevFlex = make_group(Flex, 16#f084, S0),

            {ok, TypeLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(TypeLbl, [Label]),
            ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
            {ok, DevLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(DevLbl, [DevName0]),

            {ok, Row} = lv_obj:create(Inst, DevFlex),
            ok = lv_obj:add_style(Row, RowStyle),

            {ok, MethodBtn} = lv_btn:create(Row),
            {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
            ok = lv_label:set_text(MethodBtnLbl, [<<"Use ">>, Label]),

            case HasWebAuthn of
                false ->
                    ok = lv_obj:add_state(MethodBtn, disabled),
                    {ok, HelpLbl} = lv_label:create(DevFlex),
                    ok = lv_label:set_text(HelpLbl, [
                        "Enable WebAuthN redirection to use ", Label]),
                    #{role := RoleStyle} = Sty,
                    ok = lv_obj:add_style(HelpLbl, RoleStyle),
                    Acc0;
                true ->
                    Payload = #{authenticator => Label},
                    {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn,
                        short_clicked, {select, MethodBtn, Payload}),
                    [MethodBtnEvt | Acc0]
            end;

        (#{authenticator := {app, Com, EIs}, label := Label,
                properties := #{method_type := {choice, _, MethodOpts}}}, Acc0) ->
            MethodChoices = lists:foldl(fun (#{label := L, value := V}, MCAcc) ->
                Method = binary_to_atom(V, utf8),
                MCAcc#{Method => L}
            end, #{}, MethodOpts),
            MethodGroups = lists:foldl(fun (EI, MGAcc) ->
                Methods = maps:get(methods, EI, maps:get(methods, Com)),
                MG0 = maps:get(Methods, MGAcc, []),
                MGAcc#{Methods => [EI | MG0]}
            end, #{}, EIs),
            maps:fold(fun
                ([signed_nonce], _MethodEIs, Acc00) ->
                    Acc00;
                (Methods, MethodEIs, Acc00) ->
                    DevNames = lists:uniq([D || #{device_name := D} <- MethodEIs]),
                    DevName0 = iolist_to_binary(lists:join(<<"\n">>, DevNames)),

                    DevFlex = make_group(Flex, 16#f10b, S0),

                    {ok, TypeLbl} = lv_label:create(DevFlex),
                    ok = lv_label:set_text(TypeLbl, [Label]),
                    ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
                    {ok, DevLbl} = lv_label:create(DevFlex),
                    ok = lv_label:set_text(DevLbl, [DevName0]),

                    {ok, Row} = lv_obj:create(Inst, DevFlex),
                    ok = lv_obj:add_style(Row, RowStyle),

                    lists:foldl(fun (Method, Acc000) ->
                        #{Method := L} = MethodChoices,

                        {ok, MethodBtn} = lv_btn:create(Row),
                        {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
                        ok = lv_label:set_text(MethodBtnLbl, L),

                        Payload = #{authenticator => {Label, #{method_type => L}}},
                        {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn,
                            short_clicked, {select, MethodBtn, Payload}),
                        [MethodBtnEvt | Acc000]
                    end, Acc00, Methods)
            end, Acc0, MethodGroups);

        (#{authenticator := {app, _Com, EIs}, label := Label,
                properties := Props}, Acc0) when map_size(Props) == 0 ->
            DevNames = lists:uniq([D || #{device_name := D} <- EIs]),
            DevName0 = iolist_to_binary(lists:join(<<"\n">>, DevNames)),

            DevFlex = make_group(Flex, 16#f10b, S0),

            {ok, TypeLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(TypeLbl, [Label]),
            ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
            {ok, DevLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(DevLbl, [DevName0]),

            {ok, Row} = lv_obj:create(Inst, DevFlex),
            ok = lv_obj:add_style(Row, RowStyle),

            {ok, MethodBtn} = lv_btn:create(Row),
            {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
            ok = lv_label:set_text(MethodBtnLbl, <<"Enter a code">>),

            Payload = #{authenticator => Label},
            {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn,
                short_clicked, {select, MethodBtn, Payload}),
            [MethodBtnEvt | Acc0];

        (#{authenticator := {email, #{methods := [email]}, [EI]}, label := Label}, Acc0) ->
            #{email := Email} = EI,
            DevFlex = make_group(Flex, 16#f0e0, S0),

            {ok, TypeLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(TypeLbl, [Label]),
            ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
            {ok, DevLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(DevLbl, [Email]),

            {ok, Row} = lv_obj:create(Inst, DevFlex),
            ok = lv_obj:add_style(Row, RowStyle),

            {ok, MethodBtn} = lv_btn:create(Row),
            {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
            ok = lv_label:set_text(MethodBtnLbl, <<"Receive a code via email">>),

            Payload = #{authenticator => Label},
            {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn,
                short_clicked, {select, MethodBtn, Payload}),
            [MethodBtnEvt | Acc0];

        (#{authenticator := {phone, #{methods := [sms]}, [EI]}, label := Label}, Acc0) ->
            #{number := PhNum} = EI,
            DevFlex = make_group(Flex, 16#f7cd, S0),

            {ok, TypeLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(TypeLbl, [Label]),
            ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
            {ok, DevLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(DevLbl, [PhNum]),

            {ok, Row} = lv_obj:create(Inst, DevFlex),
            ok = lv_obj:add_style(Row, RowStyle),

            {ok, MethodBtn} = lv_btn:create(Row),
            {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
            ok = lv_label:set_text(MethodBtnLbl, <<"Receive a code via SMS">>),

            Payload = #{authenticator => Label},
            {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn,
                short_clicked, {select, MethodBtn, Payload}),
            [MethodBtnEvt | Acc0];

        (#{authenticator := {tac, #{methods := [tac]}, _}, label := Label}, Acc0) ->
            DevFlex = make_group(Flex, 16#f7cd, S0),

            {ok, TypeLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(TypeLbl, [Label]),
            ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),

            {ok, Row} = lv_obj:create(Inst, DevFlex),
            ok = lv_obj:add_style(Row, RowStyle),

            {ok, MethodBtn} = lv_btn:create(Row),
            {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
            ok = lv_label:set_text(MethodBtnLbl, <<"Enter a code">>),

            Payload = #{authenticator => Label},
            {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn,
                short_clicked, {select, MethodBtn, Payload}),
            [MethodBtnEvt | Acc0];

        (_, Acc0) ->
            Acc0
    end, [], Options),

    {ok, CheckOuter} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(CheckOuter, GroupStyle),

    {ok, RememberCheck} = lv_checkbox:create(CheckOuter),
    ok = lv_checkbox:set_text(RememberCheck, "Remember this computer (skip MFA for next 10 hours)"),

    {ok, CancelBtn} = lv_btn:create(Flex),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    CancelText = case S0 of
        #?MODULE{mfa = [NextMethod | _]} ->
            ["Try another method (", string:titlecase(
                atom_to_binary(NextMethod, utf8)), ")"];
        #?MODULE{mfa = []} ->
            ["Cancel"]
    end,
    ok = lv_label:set_text(CancelBtnLbl, CancelText),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),
    Evts1 = [CancelEvt | Evts0],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S1#?MODULE{screen = Screen, events = Evts1,
                            rmbrchk = RememberCheck}};
okta_select(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
okta_select(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
okta_select(info, {Ref, {wait_release, Evt}}, S0 = #?MODULE{inst = Inst}) ->
    ok = lv_indev:wait_release(Inst, keyboard),
    okta_select(info, {Ref, Evt}, S0);
okta_select(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
okta_select(info, {_, cancel}, S0 = #?MODULE{creds = Creds0}) ->
    Creds1 = maps:remove(okta, Creds0),
    {next_state, check_mfa, S0#?MODULE{creds = Creds1}};
okta_select(info, {_, {select, Btn, Payload}}, S0 = #?MODULE{}) ->
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk, okta = Okta} = S0,
    ok = lv_obj:add_state(Btn, disabled),
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    O0 = maps:get(okta, Creds0, #{}),
    O1 = O0#{remember_me => RememberMe},
    Creds1 = Creds0#{okta => O1},
    S1 = S0#?MODULE{creds = Creds1},
    case okta:proceed(Okta, select_authenticator, Payload) of
        {ok, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            okta_next(Steps, S1);
        {ok, finished, Tokens} ->
            okta_finish(Tokens, S0);
        {warning, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        {error, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        Else ->
            lager:debug("okta proceed else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S2 = S1#?MODULE{errmsg = Msg},
            {next_state, login, S2}
    end.

okta_enter_code(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst, okta = Okta}) ->
    #{row := RowStyle, title := TitleStyle, group := GroupStyle,
      item_title := ItemTitleStyle} = Sty,

    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, {AuthType, Com, EIs}} = okta:ainfo(Okta),
    #{methods := [Method | _], remediations := Rems, name := AuthName} = Com,
    MethodEIs = lists:filter(fun (EI) ->
        Methods = maps:get(methods, EI, maps:get(methods, Com)),
        lists:member(Method, Methods)
    end, EIs),

    DevNames = lists:uniq([D || #{device_name := D} <- MethodEIs]),
    DevName0 = iolist_to_binary(lists:join(<<"\n">>, DevNames)),

    {ok, Rem} = okta:rinfo(Okta, challenge_authenticator),
    #{properties := RemProps} = Rem,

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, ["Okta ",
        string:titlecase(atom_to_binary(Method, utf8))]),
    ok = lv_span:set_style(Title, TitleStyle),

    S1 = case S0 of
        #?MODULE{errmsg = undefined} -> S0;
        #?MODULE{errmsg = ErrMsg} ->
            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, ErrMsg),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            S0#?MODULE{errmsg = undefined}
    end,

    DevFlex = make_group(Flex, 16#f11c, S1),

    {ok, TypeLbl} = lv_label:create(DevFlex),
    ok = lv_label:set_text(TypeLbl, [AuthName]),
    ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
    case DevName0 of
        <<>> -> ok;
        _ ->
            {ok, DevLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(DevLbl, [DevName0])
    end,

    {ok, Row} = lv_obj:create(Inst, DevFlex),
    ok = lv_obj:add_style(Row, RowStyle),

    {_, InpMap} = okta:mapfold_remprops(fun
        (Path = [Name | _], {simple, FProps}, InpMap0) ->
            Label = maps:get(label, FProps,
                string:titlecase(atom_to_binary(Name, utf8))),
            {ok, CodeText} = lv_textarea:create(Row),
            ok = lv_textarea:set_one_line(CodeText, true),
            ok = lv_textarea:set_text_selection(CodeText, true),
            ok = lv_textarea:set_placeholder_text(CodeText, Label),
            case Name of
                totp ->
                    #?MODULE{pinchars = PinChars} = S0,
                    ok = lv_textarea:set_accepted_chars(CodeText, PinChars);
                _ ->
                    ok
            end,
            ok = lv_group:add_obj(InpGroup, CodeText),
            {undefined, InpMap0#{Path => CodeText}};

        (Path, {choice, _, Choices}, InpMap0) ->
            Labels = [L || #{label := L} <- Choices],
            LabelMap = maps:from_list(lists:zip(
                lists:seq(0, length(Labels)),
                Labels)),
            {ok, MapBuf} = lv:make_cstring_array(Inst, Labels),
            {ok, BtnMatrix} = lv_btnmatrix:create(Row),
            ok = lv_btnmatrix:set_map(BtnMatrix, MapBuf),
            ok = lv_btnmatrix:set_one_checked(BtnMatrix, true),
            ok = lv_btnmatrix:set_btn_ctrl_all(BtnMatrix, checkable),
            ok = lv_btnmatrix:set_btn_ctrl(BtnMatrix, 0, checked),

            #{matrix := MatrixStyle, matrix_item := MatrixItemStyle,
              matrix_item_checked := MatrixChItemStyle} = Sty,
            ok = lv_obj:add_style(BtnMatrix, MatrixStyle),
            ok = lv_obj:add_style(BtnMatrix, MatrixItemStyle, [items]),
            ok = lv_obj:add_style(BtnMatrix, MatrixChItemStyle, [items, checked]),

            {undefined, InpMap0#{Path => {BtnMatrix, LabelMap}}}
    end, #{}, RemProps),

    {ok, MethodBtn} = lv_btn:create(Row),
    {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
    ok = lv_label:set_text(MethodBtnLbl, "Submit"),

    {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, short_clicked,
        {proceed, MethodBtn, challenge_authenticator, InpMap}),
    Evts0 = [MethodBtnEvt],

    Evts1 = maps:fold(fun
        (_Path, {_Widget, _IdxMap}, Acc) -> Acc;
        (_Path, Widget, Acc) ->
            case lv_obj:has_class(Widget, lv_textarea) of
                true ->
                    {ok, Evt, _} = lv_event:setup(Widget, ready,
                        {wait_release,
                            {proceed, MethodBtn,
                             challenge_authenticator, InpMap}}),
                    [Evt | Acc];
                false -> Acc
            end
    end, Evts0, InpMap),

    {ok, BtnRow} = lv_obj:create(Inst, DevFlex),
    ok = lv_obj:add_style(BtnRow, RowStyle),

    Evts2 = lists:foldl(fun
        (send, Acc) when AuthType =:= app ->
            Acc;
        (RType, Acc) ->
            {ok, #{properties := Props}} = okta:rinfo(Okta, RType),
            RemText = string:titlecase(atom_to_binary(RType, utf8)),
            case maps:keys(Props) of
                [] ->
                    {ok, RemBtn} = lv_btn:create(BtnRow),
                    {ok, RemLbl} = lv_label:create(RemBtn),
                    ok = lv_label:set_text(RemLbl, RemText),
                    {ok, RemEvt, _} = lv_event:setup(RemBtn, short_clicked,
                        {proceed, RemBtn, RType}),
                    [RemEvt | Acc];
                _ ->
                    Acc
            end
    end, Evts1, [cancel | Rems]),

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    do_ping_annotate(S1),

    {keep_state, S1#?MODULE{screen = Screen, events = Evts2,
                            widgets = #{inp => InpGroup}}};

okta_enter_code(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
okta_enter_code(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
okta_enter_code(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
okta_enter_code(info, {_, {proceed, Btn, Rem}}, S0 = #?MODULE{okta = Okta}) ->
    ok = lv_obj:add_state(Btn, disabled),
    case okta:proceed(Okta, Rem) of
        {ok, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            okta_next(Steps, S0);
        {ok, finished, Tokens} ->
            okta_finish(Tokens, S0);
        {warning, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        {error, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        Else ->
            lager:debug("okta proceed else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, login, S1}
    end;
okta_enter_code(info, {_, {proceed, Btn, RemName, InpMap}}, S0 = #?MODULE{okta = Okta}) ->
    ok = lv_obj:add_state(Btn, disabled),
    {ok, Rem} = okta:rinfo(Okta, RemName),
    #{properties := RemProps} = Rem,
    {ok, {_Type, Com, _EIs}} = okta:ainfo(Okta),
    #{methods := [Method | _], name := AuthName} = Com,
    Args = okta:map_remprops(fun
        (Path, {simple, _}) ->
            #{Path := Widget} = InpMap,
            {ok, Text} = lv_textarea:get_text(Widget),
            Text;
        (Path, {choice, _, _}) ->
            #{Path := {Widget, IdxMap}} = InpMap,
            {ok, Idx} = lv_btnmatrix:first_btn_with_ctrl(Widget, checked),
            #{Idx := Label} = IdxMap,
            Label
    end, RemProps),
    case okta:proceed(Okta, RemName, Args) of
        {ok, next_steps, Steps} ->
            S1 = okta_add_step(Method, AuthName, S0),
            ok = lv_obj:clear_state(Btn, disabled),
            okta_next(Steps, S1);
        {ok, finished, Tokens} ->
            S1 = okta_add_step(Method, AuthName, S0),
            okta_finish(Tokens, S1);
        {warning, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_add_step(Method, AuthName, S0),
            S2 = okta_msgs_to_errmsg(Msgs, S1),
            okta_next(Steps, S2);
        {error, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        Else ->
            lager:debug("okta proceed else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, login, S1}
    end;
okta_enter_code(info, {Ref, {wait_release, Evt}}, S0 = #?MODULE{inst = Inst}) ->
    ok = lv_indev:wait_release(Inst, keyboard),
    okta_enter_code(info, {Ref, Evt}, S0).

okta_msgs_to_errmsg(Msgs, S0 = #?MODULE{}) ->
    Msg = iolist_to_binary([
        ["Okta [", atom_to_binary(C, utf8), "]: ", M, "\n"]
        || {C, M} <- Msgs]),
    S0#?MODULE{errmsg = Msg}.


okta_poll(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst, okta = Okta}) ->
    #{row := RowStyle, title := TitleStyle, instruction := InstrStyle,
      vcode := VCodeStyle, group := GroupStyle,
      item_title := ItemTitleStyle} = Sty,
    {Screen, Flex} = make_screen(S0),

    {ok, {AuthType, Com, EIs}} = okta:ainfo(Okta),
    #{methods := [Method | _], remediations := Rems, name := AuthName} = Com,

    Icon = case AuthType of
        app -> 16#f10b;
        email -> 16#f0e0;
        phone -> 16#f7cd;
        _ -> 16#f101
    end,

    MethodEIs = lists:filter(fun (EI) ->
        Methods = maps:get(methods, EI, maps:get(methods, Com)),
        lists:member(Method, Methods)
    end, EIs),
    [MethodEI | _] = MethodEIs,
    DevNames = lists:uniq([D || #{device_name := D} <- MethodEIs]),
    DevName0 = iolist_to_binary(lists:join(<<"\n">>, DevNames)),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, ["Okta ",
        string:titlecase(atom_to_binary(Method, utf8))]),
    ok = lv_span:set_style(Title, TitleStyle),

    S1 = case S0 of
        #?MODULE{errmsg = undefined} -> S0;
        #?MODULE{errmsg = ErrMsg} ->
            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, ErrMsg),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            S0#?MODULE{errmsg = undefined}
    end,

    case MethodEI of
        #{push_code := _} ->
            {ok, Instr} = lv_span:new_span(Text),
            ok = lv_span:set_text(Instr, [$\n,
                "Additional confirmation is required.\n"
                "\n - Open Okta Verify on your phone or tablet.\n"
                " - Tap the number which matches below.\n\n"]),
            ok = lv_span:set_style(Instr, InstrStyle);
        _ ->
            ok
    end,

    DevFlex = make_group(Flex, Icon, S1),

    {ok, TypeLbl} = lv_label:create(DevFlex),
    ok = lv_label:set_text(TypeLbl, [AuthName]),
    ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
    case DevName0 of
        <<>> -> ok;
        _ ->
            {ok, DevLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(DevLbl, [DevName0])
    end,

    {ok, Row} = lv_obj:create(Inst, DevFlex),
    ok = lv_obj:add_style(Row, RowStyle),

    {ok, Spinner} = lv_spinner:create(Row, 1000, 90),
    ok = lv_obj:set_size(Spinner, {45, 45}),

    {ok, SpinLbl} = lv_label:create(Row),
    ok = lv_label:set_text(SpinLbl, "Waiting for confirmation..."),

    case MethodEI of
        #{push_code := PushCode} ->
            {ok, CodeLbl} = lv_label:create(Row),
            ok = lv_obj:align(CodeLbl, right_mid),
            ok = lv_label:set_text(CodeLbl, [PushCode]),
            ok = lv_obj:add_style(CodeLbl, VCodeStyle);
        _ ->
            ok
    end,

    {ok, BtnRow} = lv_obj:create(Inst, DevFlex),
    ok = lv_obj:add_style(BtnRow, RowStyle),

    Evts = lists:foldl(fun (RType, Acc) ->
        {ok, #{properties := Props}} = okta:rinfo(Okta, RType),
        RemText = string:titlecase(atom_to_binary(RType, utf8)),
        case maps:keys(Props) of
            [] ->
                {ok, RemBtn} = lv_btn:create(BtnRow),
                {ok, RemLbl} = lv_label:create(RemBtn),
                ok = lv_label:set_text(RemLbl, RemText),
                {ok, RemEvt, _} = lv_event:setup(RemBtn, short_clicked,
                    {proceed, RemBtn, RType}),
                [RemEvt | Acc];
            _ ->
                Acc
        end
    end, [], [cancel | Rems]),

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    do_ping_annotate(S1),

    {keep_state, S1#?MODULE{screen = Screen, events = Evts},
        [{state_timeout, 500, poll}]};

okta_poll(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
okta_poll(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
okta_poll(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
okta_poll(state_timeout, poll, S0 = #?MODULE{okta = Okta}) ->
    {ok, PollInfo} = okta:rinfo(Okta, challenge_poll),
    #{refresh := PollInterval} = PollInfo,
    {ok, {_Type, Com, _EIs}} = okta:ainfo(Okta),
    #{methods := [Method | _], name := AuthName} = Com,
    case okta:proceed(Okta, challenge_poll) of
        {ok, next_steps, #{challenge_poll := #{}}} ->
            {keep_state_and_data, [{state_timeout, PollInterval, poll}]};
        {ok, next_steps, Steps} ->
            S1 = okta_add_step(Method, AuthName, S0),
            okta_next(Steps, S1);
        {ok, finished, Tokens} ->
            S1 = okta_add_step(Method, AuthName, S0),
            okta_finish(Tokens, S1);
        {warning, Msgs, next_steps, Steps} ->
            S1 = okta_add_step(Method, AuthName, S0),
            lager:debug("okta warning: ~p", [Msgs]),
            S2 = okta_msgs_to_errmsg(Msgs, S1),
            okta_next(Steps, S2);
        {error, Msgs, next_steps, Steps} ->
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        Else ->
            lager:debug("okta poll else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, login, S1}
    end;
okta_poll(info, {_, {proceed, Btn, Rem}}, S0 = #?MODULE{okta = Okta}) ->
    ok = lv_obj:add_state(Btn, disabled),
    case okta:proceed(Okta, Rem) of
        {ok, next_steps, #{challenge_poll := #{}}} ->
            ok = lv_obj:clear_state(Btn, disabled),
            keep_state_and_data;
        {ok, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            okta_next(Steps, S0);
        {ok, finished, Tokens} ->
            okta_finish(Tokens, S0);
        {warning, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        {error, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        Else ->
            lager:debug("okta proceed else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, login, S1}
    end.

okta_webauthn(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst, okta = Okta}) ->
    #{row := RowStyle, title := TitleStyle, group := GroupStyle,
      item_title := ItemTitleStyle} = Sty,
    {Screen, Flex} = make_screen(S0),

    {ok, {webauthn, Com, EIs}} = okta:ainfo(Okta),
    #{remediations := Rems, name := AuthName} = Com,
    DevNames = lists:uniq([D || #{device_name := D} <- EIs]),
    DevName0 = iolist_to_binary(lists:join(<<"\n">>, DevNames)),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, ["Okta WebAuthN"]),
    ok = lv_span:set_style(Title, TitleStyle),

    S1 = case S0 of
        #?MODULE{errmsg = undefined} -> S0;
        #?MODULE{errmsg = ErrMsg} ->
            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, ErrMsg),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            S0#?MODULE{errmsg = undefined}
    end,

    DevFlex = make_group(Flex, 16#f084, S1),

    {ok, TypeLbl} = lv_label:create(DevFlex),
    ok = lv_label:set_text(TypeLbl, [AuthName]),
    ok = lv_obj:add_style(TypeLbl, ItemTitleStyle),
    case DevName0 of
        <<>> -> ok;
        _ ->
            {ok, DevLbl} = lv_label:create(DevFlex),
            ok = lv_label:set_text(DevLbl, [DevName0])
    end,

    {ok, Row} = lv_obj:create(Inst, DevFlex),
    ok = lv_obj:add_style(Row, RowStyle),

    {ok, Spinner} = lv_spinner:create(Row, 1000, 90),
    ok = lv_obj:set_size(Spinner, {45, 45}),

    {ok, SpinLbl} = lv_label:create(Row),
    ok = lv_label:set_text(SpinLbl, ["Authenticating...\n",
        "(Touch may be required)"]),

    {ok, BtnRow} = lv_obj:create(Inst, DevFlex),
    ok = lv_obj:add_style(BtnRow, RowStyle),

    Evts = lists:foldl(fun (RType, Acc) ->
        {ok, #{properties := Props}} = okta:rinfo(Okta, RType),
        RemText = string:titlecase(atom_to_binary(RType, utf8)),
        case maps:keys(Props) of
            [] ->
                {ok, RemBtn} = lv_btn:create(BtnRow),
                {ok, RemLbl} = lv_label:create(RemBtn),
                ok = lv_label:set_text(RemLbl, RemText),
                {ok, RemEvt, _} = lv_event:setup(RemBtn, short_clicked,
                    {proceed, RemBtn, RType}),
                [RemEvt | Acc];
            _ ->
                Acc
        end
    end, [], [cancel | Rems]),

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    do_ping_annotate(S1),

    {keep_state, S1#?MODULE{screen = Screen, events = Evts},
        [{state_timeout, 0, auth}]};

okta_webauthn(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
okta_webauthn(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
okta_webauthn(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
okta_webauthn(state_timeout, auth, S0 = #?MODULE{srv = Srv, okta = Okta}) ->
    {ok, Ewa} = rdp_server:get_dvchan_pid(Srv, rdpewa_fsm),
    {ok, {webauthn, _Com, EIs = [FirstEI | _]}} = okta:ainfo(Okta),

    #{challenge := Challenge, app_id := AppId, uv_required := UVReq} = FirstEI,

    CredIdMap = lists:foldl(fun
        (EI = #{cred_id := CredId}, Acc) ->
            {ok, CredIdBin} = jose_base64url:decode(CredId),
            Acc#{CredIdBin => EI}
    end, #{}, EIs),
    CredIds = [#{id => CredId} || CredId <- maps:keys(CredIdMap)],

    #{host := Host, scheme := <<"https">>} = uri_string:parse(AppId),
    CD = #{
        <<"type">> => <<"webauthn.get">>,
        <<"challenge">> => Challenge,
        <<"origin">> => AppId,
        <<"crossOrigin">> => false
    },
    CDBin = iolist_to_binary([json:encode(CD)]),

    R = rdpewa_fsm:get_assertion(Ewa, #{
        relying_party => Host,
        client_data => CDBin,
        allowed_credentials => CredIds,
        uv => if UVReq -> required; true -> any end
        }),
    case R of
        {ok, I = #{signature := Sig, auth_data := {AuthData, _}}} ->
            DevInfo = maps:get(device, I, #{}),
            SI0 = case DevInfo of
                #{product := Product, manufacturer := Manuf} ->
                    #{device => iolist_to_binary([Manuf, <<" ">>, Product])};
                _ ->
                    #{}
            end,
            SI1 = case I of
                #{credential := #{id := UsedCredId}} ->
                    #{UsedCredId := UsedEI} = CredIdMap,
                    SI0#{name => maps:get(device_name, UsedEI),
                         aaguid => maps:get(aaguid, UsedEI)};
                _ ->
                    SI0
            end,
            Args = #{
                credentials => #{
                    authenticator_data => base64:encode(AuthData),
                    signature_data => base64:encode(Sig),
                    client_data => base64:encode(CDBin)
                }
            },
            case okta:proceed(Okta, challenge_authenticator, Args) of
                {ok, next_steps, Steps} ->
                    S1 = okta_add_step(webauthn, SI1, S0),
                    okta_next(Steps, S1);
                {ok, finished, Tokens} ->
                    S1 = okta_add_step(webauthn, SI1, S0),
                    okta_finish(Tokens, S1);
                {warning, Msgs, next_steps, Steps} ->
                    lager:debug("okta warning: ~p", [Msgs]),
                    S1 = okta_add_step(webauthn, SI1, S0),
                    S2 = okta_msgs_to_errmsg(Msgs, S1),
                    okta_next(Steps, S2);
                {error, Msgs, next_steps, Steps} ->
                    lager:debug("okta error: ~p", [Msgs]),
                    S1 = okta_msgs_to_errmsg(Msgs, S0),
                    okta_next(maps:remove(challenge_authenticator, Steps), S1);
                Else ->
                    lager:debug("okta proceed else: ~p", [Else]),
                    Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
                    S1 = S0#?MODULE{errmsg = Msg},
                    case okta:rinfo(Okta, select_authenticator) of
                        {ok, RI} -> okta_next(#{select_authenticator => RI}, S1);
                        _ -> {next_state, login, S1}
                    end
            end;
        Else ->
            lager:debug("webauthn failed: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error authenticating token:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            case okta:rinfo(Okta, select_authenticator) of
                {ok, RI} -> okta_next(#{select_authenticator => RI}, S1);
                _ -> {next_state, login, S1}
            end
    end;
okta_webauthn(info, {_, {proceed, Btn, Rem}}, S0 = #?MODULE{okta = Okta}) ->
    ok = lv_obj:add_state(Btn, disabled),
    case okta:proceed(Okta, Rem) of
        {ok, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            okta_next(Steps, S0);
        {ok, finished, Tokens} ->
            okta_finish(Tokens, S0);
        {warning, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta warning: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        {error, Msgs, next_steps, Steps} ->
            ok = lv_obj:clear_state(Btn, disabled),
            lager:debug("okta error: ~p", [Msgs]),
            S1 = okta_msgs_to_errmsg(Msgs, S0),
            okta_next(Steps, S1);
        Else ->
            lager:debug("okta proceed else: ~p", [Else]),
            Msg = iolist_to_binary(io_lib:format("Error contacting Okta:\n~p", [Else])),
            S1 = S0#?MODULE{errmsg = Msg},
            {next_state, login, S1}
    end.

check_epw(S0 = #?MODULE{cslots = undefined}) ->
    {next_state, check_shell, S0};
check_epw(S0 = #?MODULE{cslots = []}) ->
    {next_state, check_shell, S0};
check_epw(S0 = #?MODULE{creds = #{epw := _}}) ->
    {next_state, check_shell, S0};
check_epw(S0 = #?MODULE{creds = C0 = #{password := _}, cslots = Slots = [_ | _]}) ->
    EpwSlot = lists:search(fun
        (#{slot_id := piv_key_mgmt,
           pubkey := {#'ECPoint'{}, {namedCurve, _}}}) -> true;
        (_) -> false
    end, Slots),
    case EpwSlot of
        {value, #{card_id := CardId, slot_id := SlotId}} ->
            C1 = maps:remove(pin, C0),
            C2 = C1#{card_id => CardId, slot_id => SlotId},
            {next_state, offer_epw, S0#?MODULE{creds = C2}};
        _ ->
            {next_state, check_shell, S0}
    end;
check_epw(S0 = #?MODULE{}) ->
    {next_state, check_shell, S0}.

offer_epw(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst}) ->
    #{row := RowStyle, title := TitleStyle, instruction := InstrStyle} = Sty,
    {Screen, Flex} = make_screen(S0),
    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, "YubiKey account pairing"),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Instr} = lv_span:new_span(Text),
    ok = lv_span:set_text(Instr, [$\n, "The YubiKey you have plugged in can ",
        "be paired with your user login. This would allow you to log in ",
        "to your UQ account with your YubiKey PIN in future, skipping Duo MFA.\n\n"]),
    ok = lv_span:set_style(Instr, InstrStyle),

    Group = make_group(Flex, 16#f084, S0),

    #?MODULE{scard = SCard,
             creds = #{username := U, domain := D, card_id := CardId}} = S0,
    {ok, #{yk_serial := Serial}} = scard_auth_fsm:get_card(SCard, CardId),

    {ok, Lbl} = lv_label:create(Group),
    ok = lv_label:set_text(Lbl, ["Pair YubiKey #", integer_to_binary(Serial),
        "\nwith account ", U, "@", D, "?"]),

    {ok, Row} = lv_obj:create(Inst, Group),
    ok = lv_obj:add_style(Row, RowStyle),

    {ok, YesBtn} = lv_btn:create(Row),
    {ok, YesBtnLbl} = lv_label:create(YesBtn),
    ok = lv_label:set_text(YesBtnLbl, "Yes"),
    {ok, YesEvt, _} = lv_event:setup(YesBtn, short_clicked, respond_yes),

    {ok, NoBtn} = lv_btn:create(Row),
    {ok, NoBtnLbl} = lv_label:create(NoBtn),
    ok = lv_label:set_text(NoBtnLbl, "No"),
    {ok, NoEvt, _} = lv_event:setup(NoBtn, short_clicked, respond_no),

    Evts = [YesEvt, NoEvt],
    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts}};
offer_epw(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
offer_epw(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
offer_epw(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
offer_epw(info, {_, respond_no}, S0 = #?MODULE{}) ->
    lager:debug("refused epw offer"),
    {next_state, check_shell, S0};
offer_epw(info, {_, respond_yes}, S0 = #?MODULE{scard = SCard, creds = ECreds}) ->
    #{username := Username, domain := Domain, password := Password,
      card_id := CardId, slot_id := SlotId} = decrypt_creds(ECreds),
    {ok, _CI, SI} = scard_auth_fsm:get_slot(SCard, CardId, SlotId),
    #{pubkey := PubKey} = SI,
    EPW = scard_saved_pw_ra:encrypt(Password, PubKey),
    UPN = iolist_to_binary([Username, $@, Domain]),
    ok = scard_saved_pw_ra:add_password(UPN, EPW),
    {next_state, check_shell, S0}.

duo_choice(enter, _PrevState, S0 = #?MODULE{duodevs = Devs, sty = Sty,
                                            inst = Inst}) ->
    #{row := RowStyle, group := GroupStyle, title := TitleStyle,
      instruction := InstrStyle} = Sty,
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, rdpproxy:config([ui, title_mfa])),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Instr} = lv_span:new_span(Text),
    ok = lv_span:set_text(Instr, [$\n, rdpproxy:config([ui, instruction_mfa])]),
    ok = lv_span:set_style(Instr, InstrStyle),

    S1 = case S0 of
        #?MODULE{errmsg = undefined} -> S0;
        #?MODULE{errmsg = ErrMsg} ->
            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, ErrMsg),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            S0#?MODULE{errmsg = undefined}
    end,

    Evts0 = lists:foldl(fun (Dev, Acc0) ->
        #{<<"device">> := Id} = Dev,
        Name = case Dev of
            #{<<"display_name">> := N} -> N;
            #{<<"name">> := N} -> N;
            #{<<"device">> := N} -> N
        end,
        Caps = case Dev of
            #{<<"capabilities">> := C} -> C;
            #{<<"type">> := <<"token">>} ->
                [<<"token_otp">>];
            #{<<"type">> := <<"phone">>} ->
                [<<"push">>, <<"sms">>, <<"phone">>, <<"mobile_otp">>]
        end,
        Code = maps:get(<<"verification_code">>, Dev, undefined),

        lists:foldl(fun
            (<<"push">>, DevAcc0) ->
                DevFlex = make_group(Flex, 16#f101, S0),
                {ok, Row} = lv_obj:create(Inst, DevFlex),
                ok = lv_obj:add_style(Row, RowStyle),

                {ok, DevLbl} = lv_label:create(Row),
                ok = lv_label:set_text(DevLbl, Name),

                {ok, MethodBtn} = lv_btn:create(Row),
                {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
                ok = lv_label:set_text(MethodBtnLbl, "Duo Push"),
                {ok, MethodBtnEvt, _} = case Code of
                    undefined ->
                        lv_event:setup(MethodBtn, short_clicked, {push, Id});
                    _ ->
                        lv_event:setup(MethodBtn, short_clicked,
                            {push, Id, Code})
                end,

                [MethodBtnEvt | DevAcc0];
            (<<"sms">>, DevAcc0) ->
                DevFlex = make_group(Flex, 16#f7cd, S0),
                {ok, Row} = lv_obj:create(Inst, DevFlex),
                ok = lv_obj:add_style(Row, RowStyle),

                {ok, DevLbl} = lv_label:create(Row),
                ok = lv_label:set_text(DevLbl, Name),

                {ok, MethodBtn} = lv_btn:create(Row),
                {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
                ok = lv_label:set_text(MethodBtnLbl, "Send SMS codes"),
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, short_clicked,
                    {sms_codes, Id, MethodBtn}),
                [MethodBtnEvt | DevAcc0];
            (<<"phone">>, DevAcc0) ->
                DevFlex = make_group(Flex, 16#f095, S0),
                {ok, Row} = lv_obj:create(Inst, DevFlex),
                ok = lv_obj:add_style(Row, RowStyle),

                {ok, DevLbl} = lv_label:create(Row),
                ok = lv_label:set_text(DevLbl, Name),

                {ok, MethodBtn} = lv_btn:create(Row),
                {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
                ok = lv_label:set_text(MethodBtnLbl, "Phone call"),
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, short_clicked,
                    {call, Id}),
                [MethodBtnEvt | DevAcc0];
            (<<"mobile_otp">>, DevAcc0) ->
                DevFlex = make_group(Flex, 16#f0cb, S0),
                {ok, DevLbl} = lv_label:create(DevFlex),
                ok = lv_label:set_text(DevLbl, Name),

                {ok, Row} = lv_obj:create(Inst, DevFlex),
                ok = lv_obj:add_style(Row, RowStyle),

                {ok, CodeText} = lv_textarea:create(Row),
                ok = lv_textarea:set_one_line(CodeText, true),
                ok = lv_textarea:set_text_selection(CodeText, true),
                ok = lv_textarea:set_placeholder_text(CodeText, "Passcode"),
                #?MODULE{pinchars = PinChars} = S0,
                ok = lv_textarea:set_accepted_chars(CodeText, PinChars),
                %ok = lv_textarea:set_password_mode(CodeText, true),
                ok = lv_group:add_obj(InpGroup, CodeText),

                {ok, MethodBtn} = lv_btn:create(Row),
                {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
                ok = lv_label:set_text(MethodBtnLbl, "Submit"),

                {ok, CodeInpEvt, _} = lv_event:setup(CodeText, ready,
                    {wait_release, {passcode, Id, CodeText, MethodBtn}}),
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, short_clicked,
                    {passcode, Id, CodeText, MethodBtn}),

                [CodeInpEvt, MethodBtnEvt | DevAcc0];
            (<<"token_otp">>, DevAcc0) ->
                DevFlex = make_group(Flex, 16#f11c, S0),
                {ok, DevLbl} = lv_label:create(DevFlex),
                ok = lv_label:set_text(DevLbl, Name),

                {ok, Row} = lv_obj:create(Inst, DevFlex),
                ok = lv_obj:add_style(Row, RowStyle),

                {ok, CodeText} = lv_textarea:create(Row),
                ok = lv_textarea:set_one_line(CodeText, true),
                ok = lv_textarea:set_text_selection(CodeText, true),
                ok = lv_textarea:set_placeholder_text(CodeText, "Token OTP"),
                %ok = lv_textarea:set_password_mode(CodeText, true),
                ok = lv_group:add_obj(InpGroup, CodeText),

                {ok, MethodBtn} = lv_btn:create(Row),
                {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
                ok = lv_label:set_text(MethodBtnLbl, "Submit"),

                {ok, CodeInpEvt, _} = lv_event:setup(CodeText, ready,
                    {wait_release, {passcode, Id, CodeText, MethodBtn}}),
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, short_clicked,
                    {passcode, Id, CodeText, MethodBtn}),

                [CodeInpEvt, MethodBtnEvt | DevAcc0];

            (_, DevAcc0) -> DevAcc0
        end, Acc0, Caps)
    end, [], Devs),

    {ok, CheckOuter} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(CheckOuter, GroupStyle),

    {ok, RememberCheck} = lv_checkbox:create(CheckOuter),
    ok = lv_checkbox:set_text(RememberCheck, "Remember this computer (skip MFA for next 10 hours)"),

    {ok, CancelBtn} = lv_btn:create(Flex),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    CancelText = case S0 of
        #?MODULE{mfa = [NextMethod | _]} ->
            ["Try another method (", string:titlecase(
                atom_to_binary(NextMethod, utf8)), ")"];
        #?MODULE{mfa = []} ->
            ["Cancel"]
    end,
    ok = lv_label:set_text(CancelBtnLbl, CancelText),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),
    Evts1 = [CancelEvt | Evts0],

    %% TODO: add yubikey and u2f devices?

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S1#?MODULE{screen = Screen, events = Evts1,
                            rmbrchk = RememberCheck}};

duo_choice(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

duo_choice(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};

duo_choice(info, {Ref, {wait_release, Evt}}, S0 = #?MODULE{inst = Inst}) ->
    ok = lv_indev:wait_release(Inst, keyboard),
    duo_choice(info, {Ref, Evt}, S0);

duo_choice(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};

duo_choice(info, {_, cancel}, S0 = #?MODULE{}) ->
    #?MODULE{creds = Creds0} = S0,
    Creds1 = maps:remove(duo, Creds0),
    {next_state, check_mfa, S0#?MODULE{creds = Creds1}};

duo_choice(info, {_, {push, DevId}}, S0 = #?MODULE{}) ->
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk} = S0,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    Code = gen_push_code(),
    Creds1 = Creds0#{duo => #{device => DevId, method => push, code => Code,
                              remember_me => RememberMe}},
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, duo_auth, S1};

duo_choice(info, {_, {push, DevId, Code}}, S0 = #?MODULE{}) ->
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk} = S0,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    Creds1 = Creds0#{duo => #{device => DevId, method => vpush, code => Code,
                              remember_me => RememberMe}},
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, duo_auth, S1};

duo_choice(info, {_, {sms_codes, DevId, Btn}}, S0 = #?MODULE{duo = Duo}) ->
    ok = lv_obj:add_state(Btn, disabled),
    #?MODULE{creds = Creds, peer = Peer} = S0,
    #{username := U} = Creds,
    Args = #{
        <<"username">> => U,
        <<"ipaddr">> => Peer,
        <<"factor">> => <<"sms">>,
        <<"device">> => DevId
    },
    lager:debug("sending duo sms"),
    _ = duo:auth(Duo, Args),
    ok = lv_obj:clear_state(Btn, disabled),
    keep_state_and_data;

duo_choice(info, {_, {call, DevId}}, S0 = #?MODULE{}) ->
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk} = S0,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    Creds1 = Creds0#{duo => #{device => DevId, method => call,
                              remember_me => RememberMe}},
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, duo_auth, S1};

duo_choice(info, {_, {passcode, DevId, CodeText, _Btn}}, S0 = #?MODULE{}) ->
    {ok, OTP} = lv_textarea:get_text(CodeText),
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk} = S0,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    Creds1 = Creds0#{duo => #{device => DevId, method => otp, otp => OTP,
                              remember_me => RememberMe}},
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, duo_auth, S1}.

duo_auth(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying MFA details...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, {check, 3}}]};
duo_auth(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
duo_auth(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
duo_auth(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
duo_auth(state_timeout, {check, N}, S0 = #?MODULE{creds = Creds, duo = Duo,
                                             peer = Peer, duoid = DuoId}) ->
    #{username := U, duo := DuoCreds} = Creds,
    RememberMe = maps:get(remember_me, DuoCreds, false),
    case DuoCreds of
        #{method := vpush, device := DevId, code := _} ->
            PushInfo0 = duo_client_info(S0),
            PushInfo1 = uri_string:compose_query(PushInfo0),
            Args = #{
                <<"username">> => U,
                <<"ipaddr">> => Peer,
                <<"factor">> => <<"push">>,
                <<"device">> => DevId,
                <<"async">> => <<"true">>,
                <<"pushinfo">> => PushInfo1
            },
            lager:debug("doing duo vpush: ~p", [Args]),
            case duo:auth(Duo, Args) of
                {ok, R = #{<<"result">> := <<"deny">>}} ->
                    lager:debug("duo denied vpush: ~999p", [R]),
                    S1 = S0#?MODULE{errmsg = "Duo Push denied"},
                    {next_state, duo_choice, S1};
                {ok, #{<<"result">> := <<"allow">>}} ->
                    {next_state, duo_push_code, S0#?MODULE{duotx = undefined}};
                {error, {error, timeout}} when (N > 0) ->
                    lager:debug("duo auth call timed out, retrying"),
                    {keep_state_and_data, [{state_timeout, 500, {check, N - 1}}]};
                Err = {error, _} ->
                    lager:debug("duo auth error: ~999p", [Err]),
                    Msg = io_lib:format("Error contacting Duo API:\n~p", [Err]),
                    S1 = S0#?MODULE{errmsg = Msg},
                    {next_state, duo_choice, S1};
                {ok, #{<<"txid">> := TxId}} ->
                    {next_state, duo_async, S0#?MODULE{duotx = TxId}}
            end;
        #{method := push, device := DevId, code := Code} ->
            PushInfo0 = duo_client_info(S0),
            PushInfo1 = [{<<"code">>, Code} | PushInfo0],
            PushInfo2 = uri_string:compose_query(PushInfo1),
            Args = #{
                <<"username">> => U,
                <<"ipaddr">> => Peer,
                <<"factor">> => <<"push">>,
                <<"device">> => DevId,
                <<"async">> => <<"true">>,
                <<"pushinfo">> => PushInfo2
            },
            lager:debug("doing duo push: ~p", [Args]),
            case duo:auth(Duo, Args) of
                {ok, R = #{<<"result">> := <<"deny">>}} ->
                    lager:debug("duo denied push: ~999p", [R]),
                    S1 = S0#?MODULE{errmsg = "Duo Push denied"},
                    {next_state, duo_choice, S1};
                {ok, #{<<"result">> := <<"allow">>}} ->
                    {next_state, duo_push_code, S0#?MODULE{duotx = undefined}};
                {error, {error, timeout}} when (N > 0) ->
                    lager:debug("duo auth call timed out, retrying"),
                    {keep_state_and_data, [{state_timeout, 500, {check, N - 1}}]};
                Err = {error, _} ->
                    lager:debug("duo auth error: ~999p", [Err]),
                    Msg = io_lib:format("Error contacting Duo API:\n~p", [Err]),
                    S1 = S0#?MODULE{errmsg = Msg},
                    {next_state, duo_choice, S1};
                {ok, #{<<"txid">> := TxId}} ->
                    {next_state, duo_push_code, S0#?MODULE{duotx = TxId}}
            end;
        #{method := call, device := DevId} ->
            Args = #{
                <<"username">> => U,
                <<"ipaddr">> => Peer,
                <<"factor">> => <<"phone">>,
                <<"device">> => DevId,
                <<"async">> => <<"true">>
            },
            lager:debug("doing duo phone call: ~p", [Args]),
            case duo:auth(Duo, Args) of
                {ok, R = #{<<"result">> := <<"deny">>}} ->
                    lager:debug("duo denied phone call: ~999p", [R]),
                    S1 = S0#?MODULE{errmsg = "Duo Phone Call denied"},
                    {next_state, duo_choice, S1};
                {ok, #{<<"result">> := <<"allow">>}} ->
                    case RememberMe of
                        false -> ok;
                        true -> ok = remember_ra:remember({DuoId, U})
                    end,
                    check_epw(S0);
                Err = {error, _} ->
                    lager:debug("duo auth error: ~999p", [Err]),
                    S1 = S0#?MODULE{errmsg = "Error contacting Duo API"},
                    {next_state, duo_choice, S1};
                {ok, #{<<"txid">> := TxId}} ->
                    {next_state, duo_async, S0#?MODULE{duotx = TxId}}
            end;
        #{method := otp, otp := OTP} ->
            Args = #{
                <<"username">> => U,
                <<"ipaddr">> => Peer,
                <<"factor">> => <<"passcode">>,
                <<"passcode">> => OTP
            },
            lager:debug("doing duo passcode"),
            case duo:auth(Duo, Args) of
                {ok, R = #{<<"result">> := <<"deny">>}} ->
                    StatusMsg = maps:get(<<"status_msg">>, R, ""),
                    lager:debug("duo denied passcode: ~999p", [R]),
                    S1 = S0#?MODULE{errmsg = ["Duo Passcode denied: ", StatusMsg]},
                    {next_state, duo_choice, S1};
                {ok, #{<<"result">> := <<"allow">>}} ->
                    case RememberMe of
                        false -> ok;
                        true -> ok = remember_ra:remember({DuoId, U})
                    end,
                    check_epw(S0);
                {error, {error, timeout}} when (N > 0) ->
                    lager:debug("duo auth call timed out, retrying"),
                    {keep_state_and_data, [{state_timeout, 500, {check, N}}]};
                Err = {error, _} ->
                    lager:debug("duo auth error: ~999p", [Err]),
                    S1 = S0#?MODULE{errmsg = "Error contacting Duo API"},
                    {next_state, duo_choice, S1}
            end
    end.

duo_async(enter, _PrevState, S0 = #?MODULE{creds = #{duo := DuoCreds},
                                           sty = Sty, inst = Inst,
                                           res = {W, H}}) ->
    #{title := TitleStyle, instruction := InstrStyle, flex := FlexStyle,
      screen := ScreenStyle, vcode := VCodeStyle} = Sty,

    case DuoCreds of
        #{method := vpush, code := Code} ->
            {ok, Screen} = lv_scr:create(Inst),
            ok = lv_obj:add_style(Screen, ScreenStyle),

            {ok, Spinner} = lv_spinner:create(Screen, 1000, 90),
            ok = lv_obj:set_size(Spinner, {100, 100}),

            {ok, Flex} = lv_obj:create(Inst, Screen),
            ok = lv_obj:add_style(Flex, FlexStyle),

            if
                (W > H) ->
                    FlexW = if (0.2 * W < 500) -> 500; true -> {percent, 20} end,
                    ok = lv_obj:set_size(Flex, {FlexW, {percent, 100}});
                true ->
                    FlexH = H - 100 - 50,
                    ok = lv_obj:set_size(Flex, {{percent, 80}, FlexH})
            end,

            {ok, Text} = lv_span:create(Flex),
            ok = lv_obj:set_size(Text, {{percent, 100}, content}),
            ok = lv_span:set_mode(Text, break),

            {ok, Title} = lv_span:new_span(Text),
            ok = lv_span:set_text(Title, "Duo Verified Push"),
            ok = lv_span:set_style(Title, TitleStyle),

            {ok, Instr} = lv_span:new_span(Text),
            ok = lv_span:set_text(Instr, [$\n, "Enter this code on your Duo device to continue:\n"]),
            ok = lv_span:set_style(Instr, InstrStyle),

            {ok, CodeText} = lv_label:create(Flex),
            ok = lv_obj:align(CodeText, center),
            ok = lv_label:set_text(CodeText, [Code]),
            ok = lv_obj:add_style(CodeText, VCodeStyle),

            ok = lv_obj:align(CodeText, center),

            {ok, CancelBtn} = lv_btn:create(Flex),
            {ok, BtnLbl} = lv_label:create(CancelBtn),
            ok = lv_label:set_text(BtnLbl, "Cancel"),
            {ok, BtnEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),

            ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

            do_ping_annotate(S0),

            {keep_state, S0#?MODULE{screen = Screen, events = [BtnEvt]},
                [{state_timeout, 500, check}]};
        _ ->
            Screen = make_waiting_screen("Waiting for Duo...", S0),
            {ok, CancelBtn} = lv_btn:create(Screen),
            {ok, BtnLbl} = lv_label:create(CancelBtn),
            ok = lv_label:set_text(BtnLbl, "Cancel"),
            {ok, BtnEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),
            do_ping_annotate(S0),
            {keep_state, S0#?MODULE{screen = Screen, events = [BtnEvt]},
                [{state_timeout, 500, check}]}
    end;
duo_async(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
duo_async(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
duo_async(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
duo_async(state_timeout, check, S0 = #?MODULE{duo = Duo, duotx = TxId}) ->
    #?MODULE{creds = #{username := U, duo := DuoCreds}} = S0,
    RememberMe = maps:get(remember_me, DuoCreds, false),
    case duo:auth_status(Duo, TxId) of
        {ok, #{<<"result">> := <<"waiting">>}} ->
            {keep_state, S0, [{state_timeout, 1000, check}]};
        {ok, #{<<"result">> := <<"deny">>, <<"status_msg">> := StatusMsg}} ->
            S1 = S0#?MODULE{errmsg = ["Duo MFA denied: ", StatusMsg]},
            {next_state, duo_choice, S1};
        {ok, #{<<"result">> := <<"deny">>}} ->
            S1 = S0#?MODULE{errmsg = "Duo MFA denied"},
            {next_state, duo_choice, S1};
        {ok, #{<<"result">> := <<"allow">>}} ->
            lager:debug("duo allowed auth, proceeding"),
            #?MODULE{duoid = DuoId} = S0,
            case RememberMe of
                false -> ok;
                true -> ok = remember_ra:remember({DuoId, U})
            end,
            check_epw(S0);
        _ ->
            {keep_state, S0, [{state_timeout, 1000, check}]}
    end;
duo_async(info, {_, cancel}, S0 = #?MODULE{}) ->
    % start a new duo client on cancel, to make sure it doesn't get stuck
    {ok, Duo} = duo:start_link(),
    S1 = S0#?MODULE{errmsg = "Cancelled", duo = Duo},
    {next_state, duo_choice, S1}.

duo_push_code(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst}) ->
    #{row := RowStyle, title := TitleStyle, instruction := InstrStyle} = Sty,
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, "Duo Push confirmation"),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Instr} = lv_span:new_span(Text),
    ok = lv_span:set_text(Instr, [$\n, "Additional confirmation is required "
        "with Duo Push.\n\n - Open the Duo App on your phone or tablet.\n"
        " - Find the 4-digit code before approving the Push.\n - Enter "
        "the code below.\n - Then press Approve on your device.\n"]),
    ok = lv_span:set_style(Instr, InstrStyle),

    Group = make_group(Flex, 16#f084, S0),
    {ok, Lbl} = lv_label:create(Group),
    ok = lv_label:set_text(Lbl, "Push confirmation code:"),

    {ok, Row} = lv_obj:create(Inst, Group),
    ok = lv_obj:add_style(Row, RowStyle),

    {ok, CodeText} = lv_textarea:create(Row),
    ok = lv_textarea:set_one_line(CodeText, true),
    ok = lv_textarea:set_text_selection(CodeText, true),
    ok = lv_textarea:set_placeholder_text(CodeText, "Code (4 digits)"),
    #?MODULE{pinchars = PinChars} = S0,
    ok = lv_textarea:set_accepted_chars(CodeText, PinChars),
    ok = lv_textarea:set_max_length(CodeText, 4),
    %ok = lv_textarea:set_password_mode(CodeText, true),
    ok = lv_group:add_obj(InpGroup, CodeText),

    {ok, MethodBtn} = lv_btn:create(Row),
    {ok, MethodBtnLbl} = lv_label:create(MethodBtn),
    ok = lv_label:set_text(MethodBtnLbl, "Submit"),

    {ok, CodeInpEvt, _} = lv_event:setup(CodeText, ready,
        {wait_release, {code, CodeText}}),
    {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, short_clicked,
        {code, CodeText}),

    {ok, CancelBtn} = lv_btn:create(Flex),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(CancelBtnLbl, "Cancel"),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),

    #?MODULE{res = {W, _H}} = S0,
    if
        (W >= 1600) ->
            {ok, Img} = lv_img:create(Screen),
            ok = lv_img:set_src(Img, rdp_lvgl_server:find_image_path(rdpproxy,
                "push-confirm-code.png")),
            ok = lv_obj:add_flag(Img, ignore_layout),
            ok = lv_obj:align(Img, bottom_right),
            ok = lv_obj:move_background(Img);
        true ->
            ok
    end,

    Evts = [CodeInpEvt, MethodBtnEvt, CancelEvt],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts}};

duo_push_code(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

duo_push_code(info, {Ref, {wait_release, Evt}}, S0 = #?MODULE{inst = Inst}) ->
    ok = lv_indev:wait_release(Inst, keyboard),
    duo_push_code(info, {Ref, Evt}, S0);

duo_push_code(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};

duo_push_code(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};

duo_push_code(info, {_, {code, CodeText}}, S0 = #?MODULE{creds = Creds}) ->
    #?MODULE{duotx = DuoTx} = S0,
    #{duo := #{method := push, code := WantCode}} = Creds,
    {ok, Code} = lv_textarea:get_text(CodeText),
    case {Code, DuoTx} of
        {WantCode, undefined} ->
            check_epw(S0);
        {WantCode, _} ->
            {next_state, duo_async, S0};
        _ ->
            lager:debug("duo push verification code incorrect"),
            #?MODULE{inst = Inst, screen = Screen, sty = Sty} = S0,
            #{group := GroupStyle} = Sty,
            {ok, Flex} = lv_obj:get_child(Screen, 1),

            {ok, ErrOuter} = lv_obj:create(Inst, Flex),
            ok = lv_obj:add_style(ErrOuter, GroupStyle),
            {ok, ErrLbl} = lv_label:create(ErrOuter),
            ok = lv_label:set_text(ErrLbl, "Invalid push confirmation code"),
            ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),
            ok = lv_obj:move_to_index(ErrOuter, 1),

            ok = lv_textarea:set_text(CodeText, ""),
            ok = lv_group:focus_obj(CodeText),

            keep_state_and_data
    end;

duo_push_code(info, {_, cancel}, S0 = #?MODULE{creds = Creds0}) ->
    Creds1 = maps:remove(duo, Creds0),
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, duo_choice, S1}.

gen_push_code() ->
    <<N:32/big>> = crypto:strong_rand_bytes(4),
    iolist_to_binary(io_lib:format("~4..0B", [N rem 10000])).

duo_client_info(#?MODULE{tsudcore = TsudCore, srv = Srv}) ->
    [Name|_] = binary:split(unicode:characters_to_binary(
        TsudCore#tsud_core.client_name, {utf16, little}, utf8), [<<0>>]),
    [Maj,Min] = TsudCore#tsud_core.version,
    Version = iolist_to_binary(
        io_lib:format("version ~B.~B build ~w",
            [Maj, Min, TsudCore#tsud_core.client_build])),
    Caps = rdp_server:get_caps(Srv),
    GeneralCap = lists:keyfind(ts_cap_general, 1, Caps),
    [OsMaj, OsMin] = GeneralCap#ts_cap_general.os,
    OS = iolist_to_binary(
        io_lib:format("~w/~w", [OsMaj, OsMin])),
    [{<<"client_name">>, Name},
     {<<"client_version">>, Version},
     {<<"client_os">>, OS}].

check_shell(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Checking shell mode...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, check}]};
check_shell(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_shell(info, {scard_ready, SCard}, S0 = #?MODULE{scard = SCard}) ->
    {ok, Slots} = scard_auth_fsm:list_valid_slots(SCard),
    {keep_state, S0#?MODULE{cslots = Slots}};
check_shell(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
check_shell(state_timeout, check, S0 = #?MODULE{srv = Srv, listener = L}) ->
    Mode = rdpproxy:config([frontend, L, mode], pool),
    case Mode of
        nms_choice ->
            Shell = rdp_server:get_shell(Srv),
            lager:debug("shell = ~p", [Shell]),
            case frontend:parse_shell(Shell) of
                {none, _, _} ->
                    {next_state, nms_choice, S0};
                {Hostname, Opts, _} ->
                    #?MODULE{creds = Creds0} = S0,
                    Creds1 = case lists:member(no_forward_creds, Opts) of
                        true ->
                            maps:remove(tgts, maps:remove(password, Creds0));
                        false ->
                            Creds0
                    end,
                    S1 = S0#?MODULE{creds = Creds1,
                                    hostname = Hostname},
                    {next_state, manual_host, S1}
            end;
        {pool, Pool} ->
            {next_state, pool_host_choice, S0#?MODULE{pool = Pool}};
        pool ->
            {next_state, pool_choice, S0}
    end.

manual_host(enter, PrevState, S0 = #?MODULE{hostname = HN, inst = Inst,
                                            sty = Sty}) ->
    #{group := GroupStyle} = Sty,
    Msg = io_lib:format("Looking up '~s'...", [HN]),
    Screen = make_waiting_screen(Msg, S0),

    {ok, CancelBtn} = lv_btn:create(Screen),
    {ok, BtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(BtnLbl, "Cancel"),
    {ok, BtnEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),

    {ok, ErrGrp} = lv_obj:create(Inst, Screen),
    ok = lv_obj:set_size(ErrGrp, {{percent, 30}, content}),
    ok = lv_obj:add_flag(ErrGrp, [hidden, ignore_layout]),
    ok = lv_obj:add_style(ErrGrp, GroupStyle),
    ok = lv_obj:align(ErrGrp, center, {0, 150}),
    {ok, Icon} = lv_label:create(ErrGrp),
    ok = lv_obj:set_style_text_color(Icon, lv_color:darken(red, 2)),
    ok = lv_obj:set_style_text_font(Icon, {"lineawesome", regular, 20}),
    ok = lv_obj:align(Icon, left_mid),
    ok = lv_label:set_text(Icon, unicode:characters_to_binary([16#f071])),
    {ok, ErrLbl} = lv_label:create(ErrGrp),
    ok = lv_obj:align(ErrLbl, left_mid, {30, 0}),
    ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),

    Widgets = #{err_group => ErrGrp, err_label => ErrLbl},
    S1 = S0#?MODULE{rstate = PrevState, screen = Screen, events = [BtnEvt],
                    widgets = Widgets},

    {keep_state, S1, [{state_timeout, 100, check}]};
manual_host(state_timeout, check, S0 = #?MODULE{hostname = HostText0}) ->
    HostText1 = unicode:characters_to_list(HostText0, utf8),
    HostText2 = string:strip(HostText1, both),
    HostText = unicode:characters_to_binary(HostText2, utf8),
    case inet:parse_address(HostText2) of
        {ok, IpInet} ->
            case session_ra:get_host(HostText) of
                {ok, #{hostname := HN}} ->
                    Dev = #{ip => HostText, hostname => HN},
                    nms_choice(info, {a, {select_host, Dev}}, S0);
                _ ->
                    case http_api:rev_lookup(IpInet) of
                        {ok, RevLookupHN} ->
                            Dev = #{ip => HostText,
                                    hostname => iolist_to_binary([RevLookupHN])},
                            nms_choice(info, {a, {select_host, Dev}}, S0);
                        _ ->
                            Dev = #{ip => HostText, hostname => HostText},
                            nms_choice(info, {a, {select_host, Dev}}, S0)
                    end
            end;
        _ ->
            {ok, AllHosts} = session_ra:get_all_hosts(),
            ExactHosts = lists:filter(fun (H) ->
                case H of
                    #{hostname := HostText} -> true;
                    _ -> false
                end
            end, AllHosts),
            PrefixHosts = lists:filter(fun (H) ->
                #{hostname := HN} = H,
                case binary:match(HN, [HostText]) of
                    {0, _} -> true;
                    _ -> false
                end
            end, AllHosts),
            case {ExactHosts, PrefixHosts} of
                {[Dev], _} ->
                    nms_choice(info, {a, {select_host, Dev}}, S0);
                {[], [Dev]} ->
                    nms_choice(info, {a, {select_host, Dev}}, S0);
                _ ->
                    case inet_res:gethostbyname(HostText2) of
                        {ok, #hostent{h_name = RealName, h_addr_list = [Addr]}} ->
                            AddrBin = iolist_to_binary([inet:ntoa(Addr)]),
                            RealNameBin = iolist_to_binary([RealName]),
                            Dev = #{ip => AddrBin, hostname => RealNameBin},
                            nms_choice(info, {a, {select_host, Dev}}, S0);
                        Err ->
                            #?MODULE{widgets = #{err_group := ErrGrp,
                                                 err_label := ErrLbl}} = S0,
                            ok = lv_label:set_text(ErrLbl,
                                io_lib:format("Error while looking up '~s':\n~p",
                                    [HostText, Err])),
                            ok = lv_obj:clear_flag(ErrGrp, [hidden]),
                            lager:debug("failed to lookup ~p: ~p", [
                                HostText, Err]),
                            {keep_state_and_data, [{state_timeout, 1000, check}]}
                    end
            end
    end;
manual_host(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
manual_host(info, {scard_ready, _}, #?MODULE{}) ->
    keep_state_and_data;
manual_host(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
manual_host(info, {_, cancel}, S0 = #?MODULE{srv = Srv, rstate = check_shell}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
manual_host(info, {_, cancel}, S0 = #?MODULE{rstate = RState}) ->
    {next_state, RState, S0}.

uinfo(#?MODULE{creds = Creds, uinfo = UInfo0, peer = ClientIP, scard = SCard}) ->
    % Always include the client IP as well as the basic user info from KRB5
    UInfo1 = UInfo0#{client_ip => ClientIP},
    % Only include the card_info if we used smartcard auth
    UInfo2 = case Creds of
        #{card_id := CardId, slot_id := SlotId} ->
            {ok, CI, SI0} = scard_auth_fsm:get_slot(SCard, CardId, SlotId),
            SI1 = maps:remove(pubkey, maps:remove(cert, SI0)),
            {ok, _, CAKSI0} = scard_auth_fsm:get_slot(SCard, CardId, piv_card_auth),
            CAKSI1 = maps:remove(pubkey, maps:remove(cert, CAKSI0)),
            UInfo1#{card_info => CI#{slots =>
                #{piv_card_auth => CAKSI1, SlotId => SI1}}};
        _ ->
            UInfo1
    end,
    UInfo2.

process_acl(ConfigName, S0 = #?MODULE{}) ->
    ACL = rdpproxy:config(ConfigName, [{deny, everybody}]),
    Now = erlang:system_time(second),
    Ctx = #{time => Now, pool_availability => #{}},
    session_ra:process_rules(uinfo(S0), Ctx, ACL).

editing_host(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst, edit_host = Dev}) ->
    #{title := TitleStyle, row := RowStyle, group := GroupStyle,
      flex := FlexStyle} = Sty,

    #{hostname := Hostname, ip := IP} = Dev,
    Desc = maps:get(desc, Dev, <<>>),

    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, rdpproxy:config([ui, title_edit_host])),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Form} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(Form, FlexStyle),
    ok = lv_obj:add_style(Form, GroupStyle),
    ok = lv_obj:set_scrollbar_mode(Form, off),

    {ok, HostnameRow} = lv_obj:create(Inst, Form),
    ok = lv_obj:add_style(HostnameRow, RowStyle),
    {ok, HostnameLabel} = lv_label:create(HostnameRow),
    ok = lv_obj:set_size(HostnameLabel, {{percent, 30}, content}),
    ok = lv_label:set_text(HostnameLabel, <<"Hostname">>),
    {ok, HostnameEdit} = lv_label:create(HostnameRow),
    ok = lv_label:set_text(HostnameEdit, Hostname),

    {ok, IPRow} = lv_obj:create(Inst, Form),
    ok = lv_obj:add_style(IPRow, RowStyle),
    {ok, IPLabel} = lv_label:create(IPRow),
    ok = lv_obj:set_size(IPLabel, {{percent, 30}, content}),
    ok = lv_label:set_text(IPLabel, <<"IP address">>),
    {ok, IPEdit} = lv_label:create(IPRow),
    ok = lv_label:set_text(IPEdit, IP),

    {ok, DescRow} = lv_obj:create(Inst, Form),
    ok = lv_obj:add_style(DescRow, RowStyle),
    {ok, DescLabel} = lv_label:create(DescRow),
    ok = lv_obj:set_size(DescLabel, {{percent, 30}, content}),
    ok = lv_label:set_text(DescLabel, <<"Friendly name">>),
    {ok, DescEdit} = lv_textarea:create(DescRow),
    ok = lv_textarea:set_one_line(DescEdit, true),
    ok = lv_textarea:set_text_selection(DescEdit, true),
    ok = lv_textarea:set_text(DescEdit, Desc),
    ok = lv_obj:set_size(DescEdit, {{percent, 60}, content}),
    ok = lv_group:add_obj(InpGroup, DescEdit),

    {ok, BtnRow} = lv_obj:create(Inst, Form),
    ok = lv_obj:add_style(BtnRow, RowStyle),

    {ok, SaveBtn} = lv_btn:create(BtnRow),
    {ok, SaveBtnLbl} = lv_label:create(SaveBtn),
    ok = lv_label:set_text(SaveBtnLbl, "Save"),

    {ok, CancelBtn} = lv_btn:create(BtnRow),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(CancelBtnLbl, "Cancel"),

    {ok, SaveBtnEvt, _} = lv_event:setup(SaveBtn, short_clicked,
        {save, [{desc, DescEdit}]}),
    {ok, CancelBtnEvt, _} = lv_event:setup(CancelBtn, short_clicked,
        cancel),

    Evts = [SaveBtnEvt, CancelBtnEvt],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts}};
editing_host(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
editing_host(info, {scard_ready, _}, #?MODULE{}) ->
    keep_state_and_data;
editing_host(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
editing_host(info, {_, cancel}, S0 = #?MODULE{}) ->
    {next_state, nms_choice, S0};
editing_host(info, {_, {save, FieldMap}}, S0 = #?MODULE{edit_host = Dev0}) ->
    #{ip := IP, hostname := Hostname} = Dev0,
    _ = session_ra:create_host(#{pool => default,
                                 ip => IP,
                                 hostname => Hostname}),
    M0 = #{ip => IP, hostname => Hostname},
    M1 = lists:foldl(fun ({Field, EditWidget}, Acc) ->
        {ok, Value} = lv_textarea:get_text(EditWidget),
        Acc#{Field => Value}
    end, M0, FieldMap),
    _ = session_ra:update_host(M1),
    {next_state, nms_choice, S0}.

pool_choice(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Loading pool list...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, check}]};
pool_choice(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
pool_choice(info, {scard_ready, _}, #?MODULE{}) ->
    keep_state_and_data;
pool_choice(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
pool_choice(state_timeout, check, S0 = #?MODULE{sty = Sty, inst = Inst}) ->
    #{title := TitleStyle, instruction := InstrStyle,
      item_title := ItemTitleStyle, role := RoleStyle} = Sty,

    {ok, Pools} = session_ra:get_pools_for(uinfo(S0)),

    ShowAdmin = (process_acl([ui, admin_acl], S0) =:= allow),
    ShowNMSPool = ShowAdmin orelse (process_acl([ui, pool_nms_acl], S0) =:= allow),

    case Pools of
        [#{id := ID}] when (not ShowNMSPool) ->
            {next_state, pool_host_choice, S0#?MODULE{pool = ID}};

        _ ->
            {Screen, Flex} = make_wide_screen(S0),
            {ok, InpGroup} = lv_group:create(Inst),

            {ok, Text} = lv_span:create(Flex),
            ok = lv_obj:set_size(Text, {{percent, 100}, content}),
            ok = lv_span:set_mode(Text, break),

            {ok, Title} = lv_span:new_span(Text),
            ok = lv_span:set_text(Title, rdpproxy:config([ui, title_choose_pool])),
            ok = lv_span:set_style(Title, TitleStyle),

            {ok, Instr} = lv_span:new_span(Text),
            ok = lv_span:set_text(Instr, [$\n, rdpproxy:config([ui,
                instruction_choose_pool])]),
            ok = lv_span:set_style(Instr, InstrStyle),

            {ok, List} = lv_list:create(Flex),
            ok = lv_obj:set_size(List, {{percent, 100}, content}),
            ok = lv_obj:set_style_max_height(List, {percent, 70}),
            Evts0 = case ShowNMSPool of
                true ->
                    {ok, _} = lv_list:add_text(List, "Special options"),
                    {ok, NmsOpt} = lv_list:add_btn(List, none, none),

                    {ok, NmsIcon} = lv_label:create(NmsOpt),
                    ok = lv_obj:set_style_text_font(NmsIcon, {"lineawesome", regular, 16}),
                    ok = lv_label:set_text(NmsIcon, unicode:characters_to_binary([16#f015], utf8)),
                    ok = lv_obj:align(NmsIcon, left_mid),
                    ok = lv_obj:set_size(NmsIcon, {{percent, 2}, content}),

                    {ok, NmsLbl} = lv_label:create(NmsOpt),
                    ok = lv_label:set_text(NmsLbl, "NMS"),
                    ok = lv_obj:add_style(NmsLbl, ItemTitleStyle),
                    ok = lv_obj:set_size(NmsLbl, {{percent, 35}, content}),

                    {ok, NmsSubLbl} = lv_label:create(NmsOpt),
                    ok = lv_label:set_text(NmsSubLbl,
                        "Choose from hosts personally assigned to you in EAIT NMS."),
                    ok = lv_obj:add_style(NmsSubLbl, RoleStyle),
                    ok = lv_obj:set_size(NmsSubLbl, {{percent, 63}, content}),

                    ok = lv_group:add_obj(InpGroup, NmsOpt),
                    {ok, NmsEvt, _} = lv_event:setup(NmsOpt, short_clicked, nms_choice),
                    [NmsEvt];
                false ->
                    []
            end,

            {ok, _} = lv_list:add_text(List, "Available pools"),
            Evts1 = lists:foldl(fun (PoolInfo, Acc) ->
                #{id := ID, title := PoolTitle, help_text := HelpText} = PoolInfo,
                {ok, PoolOpt} = lv_list:add_btn(List, none, none),

                {ok, PoolIcon} = lv_label:create(PoolOpt),
                ok = lv_obj:set_style_text_font(PoolIcon, {"lineawesome", regular, 16}),
                ok = lv_label:set_text(PoolIcon, unicode:characters_to_binary([16#f6ff], utf8)),
                ok = lv_obj:align(PoolIcon, left_mid),
                ok = lv_obj:set_size(PoolIcon, {{percent, 2}, content}),

                {ok, PoolLbl} = lv_label:create(PoolOpt),
                ok = lv_label:set_text(PoolLbl, PoolTitle),
                ok = lv_obj:add_style(PoolLbl, ItemTitleStyle),
                ok = lv_obj:set_size(PoolLbl, {{percent, 35}, content}),


                {ok, PoolSubLbl} = lv_label:create(PoolOpt),
                ok = lv_label:set_text(PoolSubLbl, HelpText),
                ok = lv_obj:set_size(PoolSubLbl, {{percent, 63}, content}),
                ok = lv_obj:add_style(PoolSubLbl, RoleStyle),
                ok = lv_group:add_obj(InpGroup, PoolOpt),

                {ok, PoolEvt, _} = lv_event:setup(PoolOpt, short_clicked, {pool, ID}),
                [PoolEvt | Acc]
            end, Evts0, Pools),

            ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

            ok = lv_indev:set_group(Inst, keyboard, InpGroup),

            {keep_state, S0#?MODULE{screen = Screen, events = Evts1}}
    end;

pool_choice(info, {_, nms_choice}, S0 = #?MODULE{}) ->
    {next_state, nms_choice, S0};

pool_choice(info, {_, {pool, ID}}, S0 = #?MODULE{}) ->
    S1 = S0#?MODULE{pool = ID},
    {next_state, pool_host_choice, S1}.

pool_host_choice(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Loading computer list...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, check}]};
pool_host_choice(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
pool_host_choice(info, {scard_ready, _}, #?MODULE{}) ->
    keep_state_and_data;
pool_host_choice(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
pool_host_choice(state_timeout, check, S0 = #?MODULE{pool = Pool, creds = Creds}) ->
    #{username := U} = Creds,
    case session_ra:get_pool(Pool) of
        {ok, #{choice := true}} ->
            {ok, Prefs} = session_ra:get_prefs(Pool, U),
            Devs0 = lists:map(fun (Ip) ->
                {ok, Dev} = session_ra:get_host(Ip),
                #{handles := Hdls} = Dev,
                HDs = lists:map(fun (Hdl) ->
                    {ok, HD} = session_ra:get_handle(Hdl),
                    HD
                end, Hdls),
                Dev#{handles => HDs}
            end, Prefs),
            AnyAvail = lists:any(fun (Dev) ->
                #{handles := HDs, report_state := {St, _When}} = Dev,
                OtherUserHDs = lists:filter(fun
                    (#{user := U2}) when (U2 =:= U) -> false;
                    (_) -> true
                end, HDs),
                case {OtherUserHDs, St} of
                    {[], available} -> true;
                    _ -> false
                end
            end, Devs0),
            Devs1 = lists:map(fun (Dev) ->
                #{handles := HDs, report_state := {St, _When},
                  role := Role, alloc_history := AQ} = Dev,
                OtherUserHDs = lists:filter(fun
                    (#{user := U2}) when (U2 =:= U) -> false;
                    (_) -> true
                end, HDs),
                OurAllocs = lists:filter(fun
                    (#{user := U2}) when (U2 =:= U) -> true;
                    (_) -> false
                end, queue:to_list(AQ)),
                OurAllocsSorted = lists:sort(fun
                    (#{time := Start0}, #{time := Start1}) ->
                        (Start0 >= Start1)
                end, OurAllocs),
                LastAlloc = case OurAllocsSorted of
                    [A | _] -> A;
                    _ -> none
                end,
                Busy = case {AnyAvail, OtherUserHDs, St} of
                    % Always allow selecting available machines with 0 handles
                    {_, [], available} -> false;
                    % Also allow selecting "busy" machines without any active
                    % handles
                    {_, [], busy} -> false;
                    % Allow selecting machines with active handles if
                    % there are no available machines
                    {false, _, _} -> false;
                    _ -> true
                end,
                RoleBin = if
                    Role =:= none -> none;
                    is_binary(Role) -> Role;
                    is_atom(Role) -> atom_to_binary(Role, latin1)
                end,
                Dev#{busy => Busy, role => RoleBin, last_alloc => LastAlloc}
            end, Devs0),
            {keep_state_and_data, [{state_timeout, 100, {display, Devs1}}]};

        {ok, #{choice := false}} ->
            {next_state, alloc_handle, S0};

        Err ->
            lager:debug("get_pool error: ~999p", [Err]),
            {keep_state_and_data, [{state_timeout, 1000, check}]}
    end;
pool_host_choice(state_timeout, {display, Devs}, S0 = #?MODULE{sty = Sty}) ->
    #?MODULE{inst = Inst, pool = Pool} = S0,
    #{item_title := ItemTitleStyle, title := TitleStyle,
      item_title_faded := ItemTitleFadedStyle, instruction := InstrStyle,
      role := RoleStyle, row := RowStyle} = Sty,

    {Screen, Flex} = make_wide_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, rdpproxy:config([ui, title_choose])),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Instr} = lv_span:new_span(Text),
    ok = lv_span:set_text(Instr, [$\n, rdpproxy:config([ui,
        instruction_choose])]),
    ok = lv_span:set_style(Instr, InstrStyle),

    {ok, FilterRow} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(FilterRow, RowStyle),

    {ok, Filter} = lv_textarea:create(FilterRow),
    ok = lv_textarea:set_one_line(Filter, true),
    ok = lv_textarea:set_text_selection(Filter, true),
    ok = lv_textarea:set_placeholder_text(Filter, "search"),
    ok = lv_group:add_obj(InpGroup, Filter),

    {ok, FiltEvt, _} = lv_event:setup(Filter, value_changed,
        {update_filter, search, Filter}),

    {ok, List} = lv_list:create(Flex),
    ok = lv_obj:set_size(List, {{percent, 100}, content}),
    ok = lv_obj:set_style_max_height(List, {percent, 70}),

    {ok, #{title := PoolTitle}} = session_ra:get_pool(Pool),
    {ok, _} = lv_list:add_text(List, PoolTitle),

    {Evts0, DevMap} = lists:foldl(fun (Dev, {EvtAcc, DevMapAcc}) ->
        #{ip := IP, role := Role, last_alloc := LastAlloc} = Dev,
        Desc = maps:get(desc, Dev, none),
        Hostname = maps:get(hostname, Dev, IP),
        {ok, Opt} = lv_list:add_btn(List, none, none),

        {ok, Icon} = lv_label:create(Opt),
        ok = lv_obj:set_style_text_font(Icon, {"lineawesome", regular, 16}),
        ok = lv_label:set_text(Icon, unicode:characters_to_binary([16#f108], utf8)),
        ok = lv_obj:set_size(Icon, {{percent, 2}, content}),

        {ok, Label} = lv_span:create(Opt),
        ok = lv_obj:add_flag(Label, [clickable, event_bubble]),
        ok = lv_obj:set_size(Label, {{percent, 44}, content}),
        ok = lv_span:set_mode(Label, break),

        {HNPrefix, HNSuffix, HNStyle} = case Desc of
            none -> {[], [], ItemTitleStyle};
            <<>> -> {[], [], ItemTitleStyle};
            _ ->
                {ok, DescSpan} = lv_span:new_span(Label),
                ok = lv_span:set_text(DescSpan, [Desc]),
                ok = lv_span:set_style(DescSpan, ItemTitleStyle),
                {[$\s, $(], [$)], ItemTitleFadedStyle}
        end,
        case binary:split(Hostname, <<".">>) of
            [HostPre, HostPost] ->
                {ok, DevTitlePre} = lv_span:new_span(Label),
                ok = lv_span:set_style(DevTitlePre, HNStyle),
                ok = lv_span:set_text(DevTitlePre, [HNPrefix, HostPre]),
                {ok, DevTitlePost} = lv_span:new_span(Label),
                ok = lv_span:set_style(DevTitlePost, ItemTitleFadedStyle),
                ok = lv_span:set_text(DevTitlePost, [$., HostPost, HNSuffix]);
            [_] ->
                {ok, DevTitle} = lv_span:new_span(Label),
                ok = lv_span:set_style(DevTitle, HNStyle),
                ok = lv_span:set_text(DevTitle, [HNPrefix, Hostname, HNSuffix])
        end,
        case Role of
            none -> ok;
            <<>> -> ok;
            _ ->
                {ok, RoleSpan} = lv_span:new_span(Label),
                ok = lv_span:set_text(RoleSpan, [$\n, Role]),
                ok = lv_span:set_style(RoleSpan, RoleStyle)
        end,

        {ok, Last} = lv_label:create(Opt),
        ok = lv_obj:set_size(Last, {{percent, 32}, content}),
        case LastAlloc of
            #{time := When} ->
                ok = lv_label:set_text(Last, format_reltime(When));
            _ ->
                ok = lv_label:set_text(Last, "(never used)")
        end,

        {ok, IPLabel} = lv_label:create(Opt),
        ok = lv_obj:set_size(IPLabel, {{percent, 22}, content}),
        ok = lv_label:set_text(IPLabel, IP),
        ok = lv_obj:add_style(IPLabel, RoleStyle),

        case Dev of
            #{busy := true} ->
                ok = lv_obj:add_state(Opt, disabled),
                ok = lv_obj:set_style_opa(Opt, 0.8),
                {EvtAcc, DevMapAcc};
            _ ->
                ok = lv_group:add_obj(InpGroup, Opt),
                {ok, DevEvt, _} = lv_event:setup(Opt, short_clicked,
                    {select_host, IP}),
                {[DevEvt | EvtAcc], [{Dev, Opt} | DevMapAcc]}
        end
    end, {[], []}, Devs),

    {ok, CancelBtn} = lv_btn:create(Flex),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(CancelBtnLbl, "Back"),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),
    Evts1 = [FiltEvt, CancelEvt | Evts0],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts1, devmap = DevMap,
        filter = #{}}};

pool_host_choice(info, {_, {update_filter, search, Txt}}, S0 = #?MODULE{filter = F0}) ->
    {ok, Search} = lv_textarea:get_text(Txt),
    F1 = case Search of
        <<>> -> maps:remove(search, F0);
        _ -> F0#{search => Search}
    end,
    S1 = S0#?MODULE{filter = F1},
    filter_devmap(S1),
    {keep_state, S1};

pool_host_choice(info, {_, cancel}, S0 = #?MODULE{}) ->
    {next_state, pool_choice, S0};
pool_host_choice(info, {_, {select_host, IP}}, S0 = #?MODULE{hdl = Hdl0}) ->
    Hdl1 = Hdl0#{ip => IP},
    {next_state, alloc_handle, S0#?MODULE{hdl = Hdl1}}.

nms_choice(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Loading computer list from NMS...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
nms_choice(X, Y, S0 = #?MODULE{nms = undefined}) ->
    % if we got here via pool mode we might not have an NMS conn yet
    {ok, Nms} = nms:start_link(),
    nms_choice(X, Y, S0#?MODULE{nms = Nms});
nms_choice(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
nms_choice(info, {scard_ready, _}, #?MODULE{}) ->
    keep_state_and_data;
nms_choice(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
nms_choice(state_timeout, check, #?MODULE{nms = Nms, creds = Creds}) ->
    #{username := U} = Creds,
    case nms:get_user_hosts(Nms, U) of
        {ok, D} ->
            {keep_state_and_data, [{state_timeout, 200, {menu, D}}]};
        Err ->
            lager:debug("failed to get user hosts from nms: ~p", [Err]),
            {keep_state_and_data, [{state_timeout, 200, check}]}
    end;
nms_choice(state_timeout, {menu, Devs0}, S0 = #?MODULE{creds = Creds,
                                                       sty = Sty, inst = Inst,
                                                       listener = L}) ->
    #{title := TitleStyle, instruction := InstrStyle,
      item_title := ItemTitleStyle, item_title_faded := ItemTitleFadedStyle,
      role := RoleStyle, row := RowStyle} = Sty,
    #{username := U} = Creds,

    Now = erlang:system_time(second),
    Devs1 = lists:map(fun (Dev0) ->
        #{ip := IP} = Dev0,
        Dev1 = case session_ra:get_host(IP) of
            {ok, #{role := Role, alloc_history := AQ} = DMD} ->
                OurAllocs = lists:filter(fun
                    (#{user := U2}) when (U2 =:= U) -> true;
                    (_) -> false
                end, queue:to_list(AQ)),
                OurAllocsSorted = lists:sort(fun
                    (#{time := Start0}, #{time := Start1}) ->
                        (Start0 >= Start1)
                end, OurAllocs),
                LastAlloc = case OurAllocsSorted of
                    [A | _] -> A;
                    _ -> none
                end,
                RoleBin = if
                    Role =:= none -> none;
                    is_binary(Role) -> Role;
                    is_atom(Role) -> atom_to_binary(Role, latin1)
                end,
                Dev11 = Dev0#{role => RoleBin, last_alloc => LastAlloc},
                case DMD of
                    #{desc := Desc} when byte_size(Desc) > 0 ->
                        Dev11#{desc => Desc};
                    _ ->
                        Dev11
                end;
            _ ->
                Dev0
        end,
        Building = get_key_nullable(building, Dev1, "Building unknown"),
        Room = get_key_nullable(room, Dev1, ""),
        Class = get_key_nullable(class, Dev1, "Misc"),
        Group = case maps:get(last_alloc, Dev1, none) of
            #{time := T} when (T >= (Now - 3600*24*4*7)) ->
                recent;
            _ ->
                [Building, " - ", Class]
        end,
        Dev1#{building => Building, room => Room, group => Group}
    end, Devs0),
    Grouped = lists:foldl(fun (Dev, Acc0) ->
        #{group := Group} = Dev,
        L0 = maps:get(Group, Acc0, []),
        Acc0#{Group => L0 ++ [Dev]}
    end, #{recent => []}, Devs1),

    {Screen, Flex} = make_wide_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, Text} = lv_span:create(Flex),
    ok = lv_obj:set_size(Text, {{percent, 100}, content}),
    ok = lv_span:set_mode(Text, break),

    {ok, Title} = lv_span:new_span(Text),
    ok = lv_span:set_text(Title, rdpproxy:config([ui, title_choose])),
    ok = lv_span:set_style(Title, TitleStyle),

    {ok, Instr} = lv_span:new_span(Text),
    ok = lv_span:set_text(Instr, [$\n, rdpproxy:config([ui,
        instruction_choose])]),
    ok = lv_span:set_style(Instr, InstrStyle),

    {ok, FilterRow} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(FilterRow, RowStyle),

    {ok, Filter} = lv_textarea:create(FilterRow),
    ok = lv_textarea:set_one_line(Filter, true),
    ok = lv_textarea:set_text_selection(Filter, true),
    ok = lv_textarea:set_placeholder_text(Filter, "search"),
    ok = lv_group:add_obj(InpGroup, Filter),

    {ok, FiltEvt, _} = lv_event:setup(Filter, value_changed,
        {update_filter, search, Filter}),

    {ok, Mine} = lv_checkbox:create(FilterRow),
    ok = lv_obj:set_style_text_color(Mine, lv_color:palette(white)),
    ok = lv_checkbox:set_text(Mine, "Owned by me"),
    ok = lv_checkbox:check(Mine),

    {ok, MineEvt, _} = lv_event:setup(Mine, value_changed,
        {update_filter, mine, Mine}),

    {ok, Shared} = lv_checkbox:create(FilterRow),
    ok = lv_obj:set_style_text_color(Shared, lv_color:palette(white)),
    ok = lv_checkbox:set_text(Shared, "Shared with others"),
    ok = lv_checkbox:check(Shared),

    {ok, SharedEvt, _} = lv_event:setup(Shared, value_changed,
        {update_filter, shared, Shared}),

    Evts0 = [FiltEvt, MineEvt, SharedEvt],

    {ok, List} = lv_list:create(Flex),
    ok = lv_obj:set_size(List, {{percent, 100}, {percent, 70}}),

    Groups = [recent | (maps:keys(Grouped) -- [recent])],

    ShowPools = (rdpproxy:config([frontend, L, mode], pool) =:= nms_choice),
    ShowAdmin = (process_acl([ui, admin_acl], S0) =:= allow),

    {Evts1, AdminCustom, AdminCustomLabel} = case ShowAdmin of
        false -> {Evts0, undefined, undefined};
        true ->
            {ok, AdminOpt} = lv_list:add_btn(List, none, none),
            ok = lv_obj:add_flag(AdminOpt, hidden),

            {ok, AdminIcon} = lv_label:create(AdminOpt),
            ok = lv_obj:set_style_text_font(AdminIcon, {"lineawesome", regular, 16}),
            ok = lv_label:set_text(AdminIcon, unicode:characters_to_binary([16#f044], utf8)),
            ok = lv_obj:align(AdminIcon, left_mid),
            ok = lv_obj:set_size(AdminIcon, {{percent, 2}, content}),

            {ok, AdminLabel} = lv_span:create(AdminOpt),
            ok = lv_obj:add_flag(AdminLabel, [clickable, event_bubble]),
            ok = lv_obj:set_size(AdminLabel, {{percent, 80}, content}),
            ok = lv_span:set_mode(AdminLabel, break),

            {ok, Tpl} = lv_span:new_span(AdminLabel),
            ok = lv_span:set_text(Tpl, "Connect directly to "),
            ok = lv_span:set_style(Tpl, RoleStyle),

            {ok, CustomHostTxt} = lv_span:new_span(AdminLabel),
            ok = lv_span:set_text(CustomHostTxt, "blah"),
            ok = lv_span:set_style(CustomHostTxt, ItemTitleStyle),

            {ok, Suffix} = lv_span:new_span(AdminLabel),
            ok = lv_span:set_text(Suffix, " (admin only)"),
            ok = lv_span:set_style(Suffix, RoleStyle),

            ok = lv_group:add_obj(InpGroup, AdminOpt),

            {ok, AdminEvt, _} = lv_event:setup(AdminOpt, short_clicked,
                {custom_host, Filter}),
            {[AdminEvt | Evts0], AdminOpt, CustomHostTxt}
    end,

    Evts2 = case ShowPools of
        false -> Evts1;
        true ->
            {ok, Pools0} = session_ra:get_pools_for(uinfo(S0)),
            Pools1 = lists:filter(fun
                (#{id := default}) -> false;
                (_) -> true
            end, Pools0),

            Pools2 = lists:sort(fun
                (#{priority := A}, #{priority := B}) when (A =< B) -> true;
                (#{title := A}, #{title := B}) when (A =< B) -> true;
                (_, _) -> false
            end, Pools1),

            case Pools2 of
                [] -> ok;
                _ -> {ok, _} = lv_list:add_text(List, "Pools")
            end,

            lists:foldl(fun (Pool, Acc) ->
                #{id := PoolId, title := PoolTitle,
                  help_text := PoolHelpText} = Pool,

                {ok, Opt} = lv_list:add_btn(List, none, none),

                {ok, Icon} = lv_label:create(Opt),
                ok = lv_obj:set_style_text_font(Icon, {"lineawesome", regular, 16}),
                ok = lv_label:set_text(Icon, unicode:characters_to_binary([16#f247], utf8)),
                ok = lv_obj:align(Icon, left_mid),
                ok = lv_obj:set_size(Icon, {{percent, 2}, content}),

                {ok, Label} = lv_span:create(Opt),
                ok = lv_obj:add_flag(Label, [clickable, event_bubble]),
                ok = lv_obj:set_size(Label, {{percent, 80}, content}),
                ok = lv_span:set_mode(Label, break),

                {ok, DevTitle} = lv_span:new_span(Label),
                ok = lv_span:set_style(DevTitle, ItemTitleStyle),
                ok = lv_span:set_text(DevTitle, PoolTitle),

                {ok, HelpSpan} = lv_span:new_span(Label),
                ok = lv_span:set_text(HelpSpan, [$\n, PoolHelpText]),
                ok = lv_span:set_style(HelpSpan, RoleStyle),

                ok = lv_group:add_obj(InpGroup, Opt),
                {ok, DevEvt, _} = lv_event:setup(Opt, short_clicked,
                    {select_pool, PoolId}),
                [DevEvt | Acc]
            end, Evts1, Pools2)
    end,

    {Evts3, DevMap} = lists:foldl(fun (GroupKey, {EvtAcc, DevMapAcc}) ->
        #{GroupKey := GroupDevs} = Grouped,
        GroupHeading = case GroupKey of
            recent -> "Recently used (last 4w)";
            _ -> GroupKey
        end,
        case GroupDevs of
            [] -> ok;
            _ -> {ok, _} = lv_list:add_text(List, GroupHeading)
        end,
        GroupDevsSorted = lists:sort(fun
            (#{hostname := A}, #{hostname := B}) when (A =< B) -> true;
            (_, _) -> false
        end, GroupDevs),
        lists:foldl(fun (Dev, {EvtAccAcc, DevMapAccAcc}) ->
            #{ip := IP, hostname := Hostname, building := Building,
              room := Room, owner := Owner} = Dev,
            DevIcon = case Owner of
                U -> 16#f108;
                _ -> 16#f233
            end,
            Role = maps:get(role, Dev, none),
            Desc = maps:get(desc, Dev, none),
            {ok, Opt} = lv_list:add_btn(List, none, none),

            {ok, Icon} = lv_label:create(Opt),
            ok = lv_obj:set_style_text_font(Icon, {"lineawesome", regular, 16}),
            ok = lv_label:set_text(Icon, unicode:characters_to_binary([DevIcon], utf8)),
            ok = lv_obj:align(Icon, left_mid),
            ok = lv_obj:set_size(Icon, {{percent, 2}, content}),

            {ok, Label} = lv_span:create(Opt),
            ok = lv_obj:add_flag(Label, [clickable, event_bubble]),
            ok = lv_obj:set_size(Label, {{percent, 40}, content}),
            ok = lv_span:set_mode(Label, break),

            {HNPrefix, HNSuffix, HNStyle} = case Desc of
                none -> {[], [], ItemTitleStyle};
                <<>> -> {[], [], ItemTitleStyle};
                _ ->
                    {ok, DescSpan} = lv_span:new_span(Label),
                    ok = lv_span:set_text(DescSpan, [Desc]),
                    ok = lv_span:set_style(DescSpan, ItemTitleStyle),
                    {[$\s, $(], [$)], ItemTitleFadedStyle}
            end,
            case binary:split(Hostname, <<".">>) of
                [HostPre, HostPost] ->
                    {ok, DevTitlePre} = lv_span:new_span(Label),
                    ok = lv_span:set_style(DevTitlePre, HNStyle),
                    ok = lv_span:set_text(DevTitlePre, [HNPrefix, HostPre]),
                    {ok, DevTitlePost} = lv_span:new_span(Label),
                    ok = lv_span:set_style(DevTitlePost, ItemTitleFadedStyle),
                    ok = lv_span:set_text(DevTitlePost, [$., HostPost, HNSuffix]);
                [_] ->
                    {ok, DevTitle} = lv_span:new_span(Label),
                    ok = lv_span:set_style(DevTitle, HNStyle),
                    ok = lv_span:set_text(DevTitle, [HNPrefix, Hostname, HNSuffix])
            end,

            case Role of
                none -> ok;
                <<>> -> ok;
                _ ->
                    {ok, RoleSpan} = lv_span:new_span(Label),
                    ok = lv_span:set_text(RoleSpan, [$\n, Role]),
                    ok = lv_span:set_style(RoleSpan, RoleStyle)
            end,
            {ok, LocSpan} = lv_span:new_span(Label),
            ok = lv_span:set_text(LocSpan, [$\n, Building, ", ", Room]),
            ok = lv_span:set_style(LocSpan, RoleStyle),

            {ok, Last} = lv_label:create(Opt),
            ok = lv_obj:set_size(Last, {{percent, 32}, content}),
            LastAlloc = maps:get(last_alloc, Dev, none),
            case LastAlloc of
                #{time := When} ->
                    ok = lv_label:set_text(Last, format_reltime(When));
                _ ->
                    ok = lv_label:set_text(Last, "(never used)")
            end,

            {ok, IPLabel} = lv_label:create(Opt),
            ok = lv_obj:set_size(IPLabel, {{percent, 19}, content}),
            ok = lv_label:set_text(IPLabel, IP),
            ok = lv_obj:add_style(IPLabel, RoleStyle),

            {ok, EditBtn} = lv_btn:create(Opt),
            ok = lv_obj:set_style_opa(EditBtn, 0.5),
            {ok, EditIcon} = lv_label:create(EditBtn),
            ok = lv_obj:set_style_text_font(EditIcon, {"lineawesome", regular, 16}),
            ok = lv_label:set_text(EditIcon, unicode:characters_to_binary([16#f044], utf8)),

            ok = lv_group:add_obj(InpGroup, Opt),
            {ok, DevEvt, _} = lv_event:setup(Opt, short_clicked,
                {select_host, Dev}),
            {ok, EditEvt, _} = lv_event:setup(EditBtn, short_clicked,
                {edit_host, Dev}),
            {[DevEvt, EditEvt | EvtAccAcc], [{Dev, Opt} | DevMapAccAcc]}
        end, {EvtAcc, DevMapAcc}, GroupDevsSorted)
    end, {Evts2, []}, Groups),

    Mode = rdpproxy:config([frontend, L, mode], pool),
    Evts4 = case Mode of
        nms_choice ->
            Evts3;
        _ ->
            {ok, CancelBtn} = lv_btn:create(Flex),
            {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
            ok = lv_label:set_text(CancelBtnLbl, "Back"),
            {ok, CancelEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),
            [CancelEvt | Evts3]
    end,

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts4, devmap = DevMap,
                            filter = #{},
                            admin_custom = AdminCustom,
                            admin_custom_label = AdminCustomLabel}};

nms_choice(info, {_, {edit_host, Dev}}, S0 = #?MODULE{}) ->
    S1 = S0#?MODULE{edit_host = Dev},
    {next_state, editing_host, S1};

nms_choice(info, {_, {select_host, Dev}}, S0 = #?MODULE{nms = Nms}) ->
    #?MODULE{hdl = Hdl0} = S0,
    #{ip := IP, hostname := Hostname} = Dev,
    Hdl1 = Hdl0#{ip => IP, port => 3389},
    S1 = S0#?MODULE{hdl = Hdl1},
    _ = session_ra:create_host(#{pool => default,
                                 ip => IP,
                                 hostname => Hostname}),
    _ = session_ra:update_host(#{ip => IP, hostname => Hostname}),
    lager:debug("user chose host ~p/~p", [Hostname, IP]),
    Ret = nms:wol(Nms, Hostname),
    lager:debug("wol for ~p returned ~p", [Hostname, Ret]),
    {next_state, alloc_handle, S1};

nms_choice(info, {_, {select_pool, ID}}, S0 = #?MODULE{hdl = Hdl0}) ->
    Hdl1 = maps:remove(ip, maps:remove(port, Hdl0)),
    lager:debug("user chose pool ~p", [ID]),
    S1 = S0#?MODULE{pool = ID, hdl = Hdl1},
    {next_state, pool_host_choice, S1};

nms_choice(info, {_, {update_filter, search, Txt}}, S0 = #?MODULE{filter = F0}) ->
    {ok, Search} = lv_textarea:get_text(Txt),
    F1 = case Search of
        <<>> -> maps:remove(search, F0);
        _ -> F0#{search => Search}
    end,
    case S0 of
        #?MODULE{admin_custom = undefined} -> ok;
        #?MODULE{admin_custom = Custom, admin_custom_label = Lbl} ->
            case Search of
                <<>> ->
                    ok = lv_obj:add_flag(Custom, hidden);
                _ ->
                    ok = lv_span:set_text(Lbl, Search),
                    ok = lv_obj:clear_flag(Custom, hidden)
            end
    end,
    S1 = S0#?MODULE{filter = F1},
    filter_devmap(S1),
    {keep_state, S1};
nms_choice(info, {_, {update_filter, Prop, Check}}, S0 = #?MODULE{filter = F0}) ->
    {ok, Checked} = lv_checkbox:is_checked(Check),
    F1 = F0#{Prop => Checked},
    S1 = S0#?MODULE{filter = F1},
    filter_devmap(S1),
    {keep_state, S1};

nms_choice(info, {_, {custom_host, Inp}}, S0 = #?MODULE{}) ->
    {ok, Text} = lv_textarea:get_text(Inp),
    S1 = S0#?MODULE{hostname = Text},
    {next_state, manual_host, S1};

nms_choice(info, {_, cancel}, S0 = #?MODULE{}) ->
    {next_state, check_shell, S0}.

filter_devmap(#?MODULE{creds = Creds, filter = F, devmap = DevMap}) ->
    #{username := U} = Creds,
    {ToShow, ToHide} = lists:partition(fun ({Dev, _Obj}) ->
        match_filter(U, Dev, F)
    end, DevMap),
    lists:foreach(fun ({_Dev, Obj}) ->
        ok = lv_obj:clear_flag(Obj, hidden)
    end, ToShow),
    lists:foreach(fun ({_Dev, Obj}) ->
        ok = lv_obj:add_flag(Obj, hidden)
    end, ToHide).

map_get_none(Key, Map, Default) ->
    case maps:get(Key, Map, none) of
        none -> Default;
        Value -> Value
    end.

match_filter(U, Dev, F0 = #{search := Text}) ->
    #{ip := IP, hostname := Hostname} = Dev,
    Building = map_get_none(building, Dev, <<>>),
    Room = map_get_none(room, Dev, <<>>),
    Class = map_get_none(class, Dev, <<>>),
    RoleBin = map_get_none(role, Dev, <<>>),
    DescBin = map_get_none(desc, Dev, <<>>),
    Haystack = string:lowercase(unicode:characters_to_list(
        iolist_to_binary([IP, $\s, Hostname, $\s, RoleBin, $\s, DescBin, $\s,
            Building, $\s, Room, $\s, Class]))),
    Needle = string:lowercase(unicode:characters_to_list(Text)),
    case string:find(Haystack, Needle) of
        nomatch -> false;
        _ -> match_filter(U, Dev, maps:remove(search, F0))
    end;
match_filter(U, Dev, F0 = #{mine := false}) ->
    #{owner := Owner} = Dev,
    case Owner of
        U -> false;
        _ -> match_filter(U, Dev, maps:remove(mine, F0))
    end;
match_filter(U, Dev, F0 = #{shared := false}) ->
    #{owner := Owner} = Dev,
    case Owner of
        U -> match_filter(U, Dev, maps:remove(shared, F0));
        _ -> false
    end;
match_filter(_U, _Dev, _) -> true.

alloc_handle(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Allocating handle...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, start}]};
alloc_handle(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
alloc_handle(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};
alloc_handle(state_timeout, start, S0 = #?MODULE{pool = Pool, creds = ECreds,
                                                 hdl = Hdl0}) ->
    T0 = erlang:system_time(millisecond),
    Creds = decrypt_creds(ECreds),
    #{username := Username, domain := Domain} = Creds,
    Hdl1 = Hdl0#{user => Username, domain => Domain},
    Hdl2 = case Creds of
        #{password := Password} -> Hdl1#{password => Password};
        _ -> Hdl1#{password => <<>>}
    end,
    Hdl3 = case Creds of
        #{tgts := Tgts} -> Hdl2#{tgts => Tgts};
        _ -> Hdl2#{tgts => #{}}
    end,
    EHdl = session_ra:encrypt_handle(Hdl3),
    {ok, AllocPid} = host_alloc_fsm:start(Pool, EHdl),
    MRef = erlang:monitor(process, AllocPid),
    S1 = S0#?MODULE{allocpid = AllocPid, allocmref = MRef,
                    waitstart = T0},
    {next_state, alloc_waiting, S1}.

alloc_waiting(enter, _PrevState, S0 = #?MODULE{hdl = Hdl, sty = Sty,
                                               inst = Inst}) ->
    #{group := GroupStyle} = Sty,

    Msg = case Hdl of
        #{ip := B} when (byte_size(B) > 0) ->
            "Checking computer is online...";
        _ ->
            "Waiting for an available computer..."
    end,

    Screen = make_waiting_screen(Msg, S0),

    {ok, CancelBtn} = lv_btn:create(Screen),
    {ok, BtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(BtnLbl, "Cancel"),
    {ok, BtnEvt, _} = lv_event:setup(CancelBtn, short_clicked, cancel),

    {ok, ErrGrp} = lv_obj:create(Inst, Screen),
    ok = lv_obj:set_size(ErrGrp, {{percent, 30}, content}),
    ok = lv_obj:add_flag(ErrGrp, [hidden, ignore_layout]),
    ok = lv_obj:add_style(ErrGrp, GroupStyle),
    ok = lv_obj:align(ErrGrp, center, {0, 150}),
    {ok, Icon} = lv_label:create(ErrGrp),
    ok = lv_obj:set_style_text_color(Icon, lv_color:darken(red, 2)),
    ok = lv_obj:set_style_text_font(Icon, {"lineawesome", regular, 20}),
    ok = lv_obj:align(Icon, left_mid),
    ok = lv_label:set_text(Icon, unicode:characters_to_binary([16#f071])),
    {ok, ErrLbl} = lv_label:create(ErrGrp),
    ok = lv_obj:align(ErrLbl, left_mid, {30, 0}),
    ok = lv_obj:set_style_text_color(ErrLbl, lv_color:darken(red, 2)),

    Widgets = #{err_group => ErrGrp, err_label => ErrLbl},
    {keep_state, S0#?MODULE{screen = Screen, events = [BtnEvt],
                            widgets = Widgets}};
alloc_waiting(info, {_, cancel}, S0 = #?MODULE{allocpid = AllocPid,
                                               allocmref = MRef}) ->
    erlang:demonitor(MRef, [flush]),
    exit(AllocPid, kill),
    T1 = erlang:system_time(millisecond),
    #?MODULE{waitstart = T0} = S0,
    prometheus_summary:observe(rdpproxy_waiting_time_milliseconds, T1 - T0),
    prometheus_counter:inc(rdpproxy_wait_aborts_total),
    {next_state, check_shell, S0#?MODULE{allocpid = undefined,
                                         allocmref = undefined}};
alloc_waiting(info, {'DOWN', MRef, process, _, _},
                            S0 = #?MODULE{mref = MRef, allocpid = AllocPid}) ->
    exit(AllocPid, kill),
    T1 = erlang:system_time(millisecond),
    #?MODULE{waitstart = T0} = S0,
    prometheus_summary:observe(rdpproxy_waiting_time_milliseconds, T1 - T0),
    prometheus_counter:inc(rdpproxy_wait_aborts_total),
    {stop, normal, S0};
alloc_waiting(info, {alloc_persistent_error, AllocPid, Why},
                                        S0 = #?MODULE{allocpid = AllocPid}) ->
    Msg = case Why of
        bad_cert -> get_msg(err_cert, S0);
        no_ssl -> get_msg(err_ssl, S0);
        credssp_required -> get_msg(err_credssp_req, S0);
        down -> get_msg(err_unreach, S0);
        refused -> get_msg(err_refused, S0);
        _Other -> get_msg(err_other, S0)
    end,
    #?MODULE{widgets = #{err_group := ErrGrp, err_label := ErrLbl}} = S0,
    ok = lv_label:set_text(ErrLbl, Msg),
    ok = lv_obj:clear_flag(ErrGrp, [hidden]),
    keep_state_and_data;

alloc_waiting(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{allocmref = MRef}) ->
    {next_state, alloc_handle, S0};

alloc_waiting(info, {_, disconnect}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {next_state, dead, S0};

alloc_waiting(info, {allocated_session, Pid, Hdl}, S0 = #?MODULE{allocpid = Pid}) ->
    erlang:demonitor(S0#?MODULE.allocmref, [flush]),
    S1 = S0#?MODULE{hdl = Hdl, allocpid = undefined, allocmref = undefined},
    T1 = erlang:system_time(millisecond),
    #?MODULE{waitstart = T0, nms = Nms, creds = Creds, srv = {FPid,_}} = S0,
    prometheus_summary:observe(rdpproxy_waiting_time_milliseconds, T1 - T0),
    case Nms of
        undefined -> ok;
        _ ->
            #{username := U} = Creds,
            #{ip := IP} = Hdl,
            case nms:bump_count(Nms, U, IP) of
                {ok, _} -> ok;
                Else -> lager:debug("nms:bump_count returned ~p", [Else])
            end
    end,
    conn_ra:annotate(FPid, #{session => Hdl#{password => snip, tgts => snip}}),
    {next_state, redir, S1}.

redir(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Transferring connection...", S0),
    do_ping_annotate(S0),
    S1 = case S0 of
        #?MODULE{scard = undefined} -> S0;
        #?MODULE{scard = Pid} ->
            scard_auth_fsm:stop(Pid),
            S0#?MODULE{scard = undefined}
    end,
    {keep_state, S1#?MODULE{screen = Screen}, [{state_timeout, 500, redir}]};

redir(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

redir(state_timeout, redir, #?MODULE{srv = Srv, hdl = Hdl, listener = L, creds = C}) ->
    #{handle := Cookie, sessid := SessId} = Hdl,
    Flags = case C of
        #{username := _} -> [];
        #{slot := _} -> [smartcard]
    end,
    _Fqdn = rdpproxy:config([frontend, L, hostname], <<"localhost">>),
    Opts = #{
        session_id => SessId,
        cookie => <<"Cookie: msts=", Cookie/binary>>,
        flags => Flags
    },
    lager:debug("sending ts_redir"),
    rdp_server:send_redirect(Srv, Opts),
    {keep_state_and_data, [{state_timeout, 500, close}]};

redir(state_timeout, close, S0 = #?MODULE{}) ->
    {stop, normal, S0}.

format_reltime(Time) -> format_reltime(Time, true, false).
format_reltime(Time, Flavour, AbsOnly) ->
    Now = erlang:system_time(second),
    Delta = Now - Time,
    if
        (Delta > 365*24*3600) or AbsOnly ->
            calendar:system_time_to_rfc3339(Time, [
                {time_designator, $\s},
                {unit, second}]);
        true ->
            format_deltatime(Delta, Flavour)
    end.

format_deltatime(SDelta, Flavour) ->
    Delta = abs(SDelta),
    Secs = Delta rem 60,
    Mins = (Delta div 60) rem 60,
    Hrs = ((Delta div 60) div 60) rem 24,
    Days = (((Delta div 60) div 60) div 24) rem 7,
    Weeks = (((Delta div 60) div 60) div 24) div 7,
    iolist_to_binary(lists:join(" ",
    if
        (SDelta < 0) and Flavour -> ["in"];
        true -> []
    end ++
    if
        (Weeks > 0) -> [[integer_to_list(Weeks), "wk"]];
        true -> []
    end ++
    if
        (Days > 0) -> [[integer_to_list(Days), "d"]];
        true -> []
    end ++
    if
        (Hrs > 0) -> [[integer_to_list(Hrs), "hr"]];
        true -> []
    end ++
    if
        (Mins > 0) and (Days == 0) -> [[integer_to_list(Mins), "min"]];
        true -> []
    end ++
    if
        (Hrs == 0) and (Days == 0) -> [[integer_to_list(Secs), "sec"]];
        true -> []
    end ++
    if
        (SDelta > 0) and Flavour -> ["ago"];
        true -> []
    end
    )).

get_key_nullable(Key, Map, NullValue) ->
    case maps:get(Key, Map, null) of
        null -> NullValue;
        Other -> Other
    end.

-type encrypted() :: binary().

-spec encrypt(binary(), binary()) -> encrypted().
encrypt(D, MacExtraData) ->
    #{keys := KeyList} = maps:from_list(application:get_env(rdpproxy, ra, [])),
    {KeyRef, KeyNum} = lists:last(KeyList),
    Iv = crypto:strong_rand_bytes(16),
    Key = <<KeyNum:128/big>>,
    DLen = byte_size(D),
    PadLen = 16 - (DLen rem 16),
    DPad = <<D/binary, PadLen:PadLen/big-unit:8>>,
    DEnc = crypto:crypto_one_time(aes_128_cbc, Key, Iv, DPad, true),
    DMac = crypto:mac(hmac, sha256, Key,
        <<KeyRef:16/big, Iv/binary, MacExtraData/binary, DEnc/binary>>),
    <<KeyRef:16/big,
      (byte_size(Iv)):16/big, Iv/binary,
      (byte_size(DEnc)):16/big, DEnc/binary,
      (byte_size(DMac)):16/big, DMac/binary>>.

-spec decrypt(encrypted(), binary()) -> binary().
decrypt(Crypted, MacExtraData) ->
    <<KeyRef:16/big,
      IvLen:16/big, Iv:IvLen/binary,
      DEncLen:16/big, DEnc:DEncLen/binary,
      DMacLen:16/big, DMac:DMacLen/binary>> = Crypted,
    #{keys := KeyList} = maps:from_list(application:get_env(rdpproxy, ra, [])),
    KeyMap = maps:from_list(KeyList),
    #{KeyRef := KeyNum} = KeyMap,
    Key = <<KeyNum:128/big>>,
    OurMac = crypto:mac(hmac, sha256, Key,
        <<KeyRef:16/big, Iv/binary, MacExtraData/binary, DEnc/binary>>),
    OurMac = DMac,
    DPad = crypto:crypto_one_time(aes_128_cbc, Key, Iv, DEnc, false),
    PadLen = binary:last(DPad),
    DLen = byte_size(DPad) - PadLen,
    <<D:DLen/binary, PadLen:PadLen/big-unit:8>> = DPad,
    D.

-spec encrypt_creds(creds()) -> encrypted_creds().
encrypt_creds(#{encrypted := true}) -> error(already_encrypted);
encrypt_creds(C0 = #{username := U, tgts := Tgts}) ->
    Pid = term_to_binary(self()),
    TgtsCrypt = encrypt(term_to_binary(Tgts), <<Pid/binary, U/binary>>),
    C1 = encrypt_creds(maps:remove(tgts, C0)),
    C1#{tgts => TgtsCrypt};
encrypt_creds(C0 = #{username := U, tokens := Toks}) ->
    Pid = term_to_binary(self()),
    ToksCrypt = encrypt(term_to_binary(Toks), <<Pid/binary, U/binary>>),
    C1 = encrypt_creds(maps:remove(tokens, C0)),
    C1#{tokens => ToksCrypt};
encrypt_creds(C0 = #{username := U, password := Pw}) ->
    Pid = term_to_binary(self()),
    PwCrypt = encrypt(Pw, <<Pid/binary, U/binary>>),
    C1 = encrypt_creds(maps:remove(password, C0)),
    C1#{password => PwCrypt};
encrypt_creds(C0 = #{card_id := CardId, slot_id := SlotId, pin := PIN}) ->
    Pid = term_to_binary(self()),
    SlotBin = term_to_binary({CardId, SlotId}),
    PINCrypt = encrypt(PIN, <<Pid/binary, SlotBin/binary>>),
    C1 = encrypt_creds(maps:remove(pin, C0)),
    C1#{pin => PINCrypt};
encrypt_creds(C0 = #{}) -> C0#{encrypted => true}.

-spec decrypt_creds(encrypted_creds()) -> creds().
decrypt_creds(C0 = #{encrypted := true, username := U, password := PwCrypt})->
    Pid = term_to_binary(self()),
    Pw = decrypt(PwCrypt, <<Pid/binary, U/binary>>),
    C1 = decrypt_creds(maps:remove(password, C0)),
    C1#{password => Pw};
decrypt_creds(C0 = #{encrypted := true, username := U, tgts := TgtsCrypt}) ->
    Pid = term_to_binary(self()),
    Tgts = binary_to_term(decrypt(TgtsCrypt, <<Pid/binary, U/binary>>)),
    C1 = decrypt_creds(maps:remove(tgts, C0)),
    C1#{tgts => Tgts};
decrypt_creds(C0 = #{encrypted := true, username := U, tokens := ToksCrypt}) ->
    Pid = term_to_binary(self()),
    Toks = binary_to_term(decrypt(ToksCrypt, <<Pid/binary, U/binary>>)),
    C1 = decrypt_creds(maps:remove(tokens, C0)),
    C1#{tokens => Toks};
decrypt_creds(C0 = #{encrypted := true, slot_id := SlotId, card_id := CardId, pin := PINCrypt}) ->
    Pid = term_to_binary(self()),
    SlotBin = term_to_binary({CardId, SlotId}),
    PIN = decrypt(PINCrypt, <<Pid/binary, SlotBin/binary>>),
    C1 = decrypt_creds(maps:remove(pin, C0)),
    C1#{pin => PIN};
decrypt_creds(C0 = #{encrypted := true}) -> maps:remove(encrypted, C0);
decrypt_creds(_) -> error(not_encrypted).
