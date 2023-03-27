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

-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/kbd.hrl").
-include_lib("rdp_proto/include/tsud.hrl").
-include_lib("rdp_proto/include/rdpdr.hrl").

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
    check_pin/3,
    mfa_choice/3,
    mfa_auth/3,
    mfa_async/3,
    check_shell/3,
    manual_host/3,
    pool_choice/3,
    pool_host_choice/3,
    nms_choice/3,
    mfa_push_code/3,
    alloc_handle/3,
    alloc_waiting/3,
    redir/3
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

-type duo_choice_push() :: #{device => binary(), method => push,
    code => binary(), remember_me => boolean()}.
-type duo_choice_call() :: #{device => binary(), method => call,
    remember_me => boolean()}.
-type duo_choice_otp() :: #{device => binary(), method => otp,
    otp => binary(), remember_me => boolean()}.

-type duo_choice() :: duo_choice_push() | duo_choice_call() |
    duo_choice_otp().

-type password_creds() :: #{username => binary(), domain => binary(),
    password => binary(), duo => duo_choice()}.

-type smartcard_creds() :: #{slot => nist_piv:slot(), pin => binary()}.

-type creds() :: password_creds() | smartcard_creds().

-type msec() :: integer().

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
    hdl :: undefined | session_ra:handle_state(),
    uinfo :: undefined | session_ra:user_info(),
    cinfo :: undefined | scard_auth:card_info(),
    piv :: undefined | pid(),
    scard :: undefined | rdpdr_scard:state(),
    tsudcore :: undefined | #tsud_core{},
    nms :: undefined | pid(),
    hostname :: undefined | binary(),
    duo :: undefined | pid(),
    duoid :: undefined | binary(),
    errmsg :: undefined | binary(),
    duodevs :: undefined | [map()],
    rmbrchk :: undefined | lv:checkbox(),
    duotx :: undefined | binary(),
    pool :: undefined | atom(),
    allocpid :: undefined | pid(),
    allocmref :: undefined | reference(),
    waitstart :: undefined | msec(),
    rstate :: undefined | atom
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
            {ok, PinChars} = lv:make_buffer(Inst, <<"0123456789", 0>>),
            {ok, loading, #?MODULE{mref = MRef, srv = Srv, listener = L,
                                   inst = Inst, res = {W,H}, sty = Styles,
                                   pinchars = PinChars}}
    end.

make_styles(Inst, {W, H}) ->
    {ok, Scr} = lv_style:create(Inst),
    ok = lv_style:set_flex_flow(Scr, if (W > H) -> row; true -> column end),
    ok = lv_style:set_flex_align(Scr, center, center, center),
    {R, G, B} = rdpproxy:config([ui, bg_colour], {16#48, 16#20, 16#6c}),
    ok = lv_style:set_bg_color(Scr, lv_color:make(R, G, B)),

    {ok, Flex} = lv_style:create(Inst),
    ok = lv_style:set_flex_flow(Flex, column),
    ok = lv_style:set_flex_align(Flex, center, start, if (W > H) -> start; true -> center end),
    ok = lv_style:set_bg_opa(Flex, 0),
    ok = lv_style:set_border_opa(Flex, 0),

    {ok, Row} = lv_style:create(Inst),
    ok = lv_style:set_flex_flow(Row, row),
    ok = lv_style:set_flex_align(Row, start, center, center),
    ok = lv_style:set_bg_opa(Row, 0),
    ok = lv_style:set_border_opa(Row, 0),
    ok = lv_style:set_pad_top(Row, 0),
    ok = lv_style:set_pad_bottom(Row, 0),
    ok = lv_style:set_pad_left(Row, 0),
    ok = lv_style:set_pad_right(Row, 0),
    ok = lv_style:set_width(Row, {percent, 100}),
    ok = lv_style:set_height(Row, content),

    {ok, Group} = lv_style:create(Inst),
    ok = lv_style:set_bg_opa(Group, 0.7),
    ok = lv_style:set_border_opa(Group, 0),
    ok = lv_style:set_width(Group, {percent, 100}),
    ok = lv_style:set_height(Group, content),

    {ok, Divider} = lv_style:create(Inst),
    ok = lv_style:set_border_side(Divider, [left]),
    ok = lv_style:set_border_color(Divider, lv_color:palette(black)),
    ok = lv_style:set_border_opa(Divider, 0.5),
    ok = lv_style:set_pad_left(Divider, 10),
    ok = lv_style:set_pad_top(Divider, 0),
    ok = lv_style:set_pad_bottom(Divider, 0),
    ok = lv_style:set_radius(Divider, 0),

    {ok, Title} = lv_style:create(Inst),
    ok = lv_style:set_text_font(Title, {"roboto", bold, 32}),
    ok = lv_style:set_text_color(Title, lv_color:palette(white)),

    {ok, Subtitle} = lv_style:create(Inst),
    ok = lv_style:set_text_font(Subtitle, {"roboto", regular, 20}),
    ok = lv_style:set_text_color(Subtitle, lv_color:palette(white)),

    {ok, Instruction} = lv_style:create(Inst),
    ok = lv_style:set_text_font(Instruction, {"montserrat", regular, 16}),
    ok = lv_style:set_text_color(Instruction, lv_color:palette(white)),

    {ok, ItemTitle} = lv_style:create(Inst),
    ok = lv_style:set_text_font(ItemTitle, {"roboto", bold, 16}),
    ok = lv_style:set_text_decor(ItemTitle, [underline]),

    {ok, ItemTitleFaded} = lv_style:create(Inst),
    ok = lv_style:set_text_font(ItemTitleFaded, {"roboto", bold, 16}),
    ok = lv_style:set_text_decor(ItemTitleFaded, [underline]),
    ok = lv_style:set_text_opa(ItemTitleFaded, 0.8),

    {ok, Role} = lv_style:create(Inst),
    ok = lv_style:set_text_opa(Role, 0.7),

    #{screen => Scr, flex => Flex, group => Group, group_divider => Divider,
      row => Row, title => Title, subtitle => Subtitle,
      instruction => Instruction, item_title => ItemTitle,
      item_title_faded => ItemTitleFaded, role => Role}.

%% @private
callback_mode() -> [state_functions, state_enter].

%% @private
terminate(Reason, State, #?MODULE{duo = undefined, nms = undefined}) ->
    lager:debug("ui_fsm dying from state ~s due to ~999p", [State, Reason]),
    ok;
terminate(Reason, State, S0 = #?MODULE{duo = Duo}) when not (Duo =:= undefined) ->
    duo:stop(Duo),
    terminate(Reason, State, S0#?MODULE{duo = undefined});
terminate(Reason, State, S0 = #?MODULE{nms = Nms}) when not (Nms =:= undefined) ->
    nms:stop(Nms),
    terminate(Reason, State, S0#?MODULE{nms = undefined}).

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

check_scard(#?MODULE{srv = F}) ->
    case rdp_server:get_vchan_pid(F, rdpdr_fsm) of
        {ok, RdpDr} ->
            case rdpdr_fsm:get_devices(RdpDr) of
                {ok, Devs} ->
                    case lists:keyfind(rdpdr_dev_smartcard, 1, Devs) of
                        false ->
                            {error, no_scard};
                        #rdpdr_dev_smartcard{id = DevId} ->
                            case rdpdr_scard:open(RdpDr, DevId, system) of
                                {ok, SC0} ->
                                    case (catch scard_auth:check(SC0)) of
                                        {'EXIT', Why} ->
                                            lager:debug("probing scard failed:"
                                                " ~p", [Why]),
                                            {error, check_error};
                                        Other -> Other
                                    end;
                                Err ->
                                    lager:debug("failed to establish ctx: ~p",
                                        [Err])
                            end
                    end;
                Err ->
                    lager:debug("failed to get rdpdr devs: ~p", [Err]),
                    Err
            end;
        _ ->
            {error, no_rdpdr}
    end.

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
    {ok, {_LogoW, _LogoH}} = lv_obj:get_size(Logo),

    {ok, Flex} = lv_obj:create(Inst, Screen),
    ok = lv_obj:add_style(Flex, FlexStyle),

    if
        (W > H) ->
            FlexW = if (W div 3 < 500) -> 500; true -> W div 3 end,
            ok = lv_obj:set_size(Flex, {FlexW, {percent, 100}});
        true ->
            ok = lv_obj:set_size(Flex, {{percent, 80}, {percent, 66}})
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
    #{flex := FlexStyle, group := GroupStyle, group_divider := DivStyle} = Sty,

    {ok, Outer} = lv_obj:create(Inst, TopLevel),
    ok = lv_obj:add_style(Outer, GroupStyle),
    ok = lv_obj:set_scrollbar_mode(Outer, off),

    {ok, Sym} = lv_label:create(Outer),
    ok = lv_obj:set_style_text_font(Sym, {"lineawesome", regular, 20}),
    ok = lv_label:set_text(Sym, unicode:characters_to_binary([Symbol], utf8)),
    ok = lv_obj:align(Sym, left_mid),

    {ok, InnerFlex} = lv_obj:create(Inst, Outer),
    ok = lv_obj:add_style(InnerFlex, FlexStyle),
    ok = lv_obj:add_style(InnerFlex, DivStyle),
    ok = lv_obj:set_size(InnerFlex, {{percent, 100}, content}),
    ok = lv_obj:align(InnerFlex, top_left, {30, 0}),
    ok = lv_obj:set_scroll_dir(InnerFlex, [vertical]),

    InnerFlex.

make_plain_group(TopLevel, #?MODULE{inst = Inst, sty = Sty}) ->
    #{flex := FlexStyle, group := GroupStyle} = Sty,

    {ok, Outer} = lv_obj:create(Inst, TopLevel),
    ok = lv_obj:add_style(Outer, GroupStyle),
    ok = lv_obj:set_scrollbar_mode(Outer, off),

    {ok, InnerFlex} = lv_obj:create(Inst, Outer),
    ok = lv_obj:add_style(InnerFlex, FlexStyle),
    ok = lv_obj:set_size(InnerFlex, {{percent, 100}, content}),
    ok = lv_obj:align(InnerFlex, top_left),
    ok = lv_obj:set_scroll_dir(InnerFlex, [vertical]),

    InnerFlex.

%% @private
dead(enter, _PrevState, #?MODULE{}) ->
    {keep_state_and_data, [{state_timeout, 0, die}]};
dead(state_timeout, die, S0 = #?MODULE{}) ->
    {stop, normal, S0}.

%% @private
loading(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Please wait...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 500, check}]};
loading(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
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

    {ok, Duo} = duo:start_link(),
    S1 = S0#?MODULE{tsudcore = TsudCore, duoid = DuoId,
                    peer = PeerIpBin, duo = Duo},

    Mode = rdpproxy:config([frontend, L, mode], pool),
    S2 = case Mode of
        nms_choice ->
            {ok, Nms} = nms:start_link(),
            S1#?MODULE{nms = Nms};
        _ ->
            S1
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
    S3 = S2#?MODULE{creds = Creds1},

    Fsm = self(),
    spawn(fun() ->
        Res = check_scard(S3),
        Fsm ! {scard_result, Res}
    end),
    S4 = receive
        {scard_result, {ok, Piv, _Rdr, SC0, Info}} ->
            conn_ra:annotate(FPid, #{scard => Info}),
            S3#?MODULE{cinfo = Info, piv = Piv, scard = SC0};
        {scard_result, _} ->
            S3#?MODULE{cinfo = #{slots => #{}}}
    after 2000 ->
        S3#?MODULE{cinfo = #{slots => #{}}}
    end,

    case Creds1 of
        #{username := _, password := _} ->
            {next_state, check_login, S4};
        _ ->
            {next_state, login, S4}
    end.

%% @private
login(enter, _PrevState, S0 = #?MODULE{inst = Inst, sty = Sty, creds = Creds,
                                       cinfo = CInfo}) ->
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

    Evts0 = lists:foldl(fun
        ({Slot, #{valid := true, upn := [UPN | _]}}, Acc) ->
            CardFlex = make_group(Flex, 16#f2c2, S0),
            {ok, UserLbl} = lv_label:create(CardFlex),
            ok = lv_label:set_text(UserLbl, UPN),

            {ok, PinText} = lv_textarea:create(CardFlex),
            ok = lv_textarea:set_one_line(PinText, true),
            ok = lv_textarea:set_text_selection(PinText, true),
            ok = lv_textarea:set_placeholder_text(PinText, "PIN"),
            #?MODULE{pinchars = PinChars} = S0,
            ok = lv_textarea:set_accepted_chars(PinText, PinChars),
            ok = lv_textarea:set_password_mode(PinText, true),
            ok = lv_group:add_obj(InpGroup, PinText),

            {ok, CardBtn} = lv_btn:create(CardFlex),
            {ok, CardBtnLbl} = lv_label:create(CardBtn),
            ok = lv_label:set_text(CardBtnLbl, "Login"),

            {ok, YkBtnEvent, _} = lv_event:setup(CardBtn, pressed,
                {login_pin, Slot, PinText}),
            {ok, YkAcEvent, _} = lv_event:setup(PinText, ready,
                {login_pin, Slot, PinText}),

            [YkBtnEvent, YkAcEvent | Acc];
        (_Slot, Acc) ->
            Acc
    end, [], maps:to_list(maps:get(slots, CInfo, #{}))),

    UPwFlex = make_group(Flex, 16#f11c, S0),

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

    {ok, BtnEvent, _} = lv_event:setup(Btn, pressed, {login, UserText, PwText}),
    {ok, UAcEvent, _} = lv_event:setup(UserText, ready, {focus, PwText}),
    {ok, AcEvent, _} = lv_event:setup(PwText, ready, {login, UserText, PwText}),

    Evts1 = [BtnEvent, UAcEvent, AcEvent | Evts0],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    case Creds of
        #{username := Username} when (length(Evts0) == 0) ->
            ok = lv_textarea:set_text(UserText, Username),
            ok = lv_group:focus_obj(PwText);
        #{username := Username} ->
            ok = lv_textarea:set_text(UserText, Username);
        _ when (length(Evts0) == 0) ->
            ok = lv_group:focus_obj(UserText);
        _ ->
            ok
    end,

    {keep_state, S1#?MODULE{screen = Screen, events = Evts1,
                            widgets = #{flex => Flex, inp => InpGroup}}};

login(info, {scard_result, {ok, Piv, _Rdr, SC0, CInfo}}, S0 = #?MODULE{}) ->
    #?MODULE{srv = {FPid, _}, events = Evts0, widgets = Widgets} = S0,
    #{flex := Flex, inp := InpGroup} = Widgets,
    conn_ra:annotate(FPid, #{scard => CInfo}),
    S1 = S0#?MODULE{cinfo = CInfo, piv = Piv, scard = SC0},
    Evts1 = lists:foldl(fun
        ({Slot, #{valid := true, upn := [UPN | _]}}, Acc) ->
            CardFlex = make_group(Flex, 16#f2c2, S0),
            ok = lv_obj:move_to_index(CardFlex, 2),
            {ok, UserLbl} = lv_label:create(CardFlex),
            ok = lv_label:set_text(UserLbl, UPN),

            {ok, PinText} = lv_textarea:create(CardFlex),
            ok = lv_textarea:set_one_line(PinText, true),
            ok = lv_textarea:set_text_selection(PinText, true),
            ok = lv_textarea:set_placeholder_text(PinText, "PIN"),
            #?MODULE{pinchars = PinChars} = S0,
            ok = lv_textarea:set_accepted_chars(PinText, PinChars),
            ok = lv_textarea:set_password_mode(PinText, true),
            ok = lv_group:add_obj(InpGroup, PinText),

            {ok, CardBtn} = lv_btn:create(CardFlex),
            {ok, CardBtnLbl} = lv_label:create(CardBtn),
            ok = lv_label:set_text(CardBtnLbl, "Login"),

            {ok, YkBtnEvent, _} = lv_event:setup(CardBtn, pressed,
                {login_pin, Slot, PinText}),
            {ok, YkAcEvent, _} = lv_event:setup(PinText, ready,
                {login_pin, Slot, PinText}),

            [YkBtnEvent, YkAcEvent | Acc];
        (_Slot, Acc) ->
            Acc
    end, Evts0, maps:to_list(maps:get(slots, CInfo, #{}))),
    S2 = S1#?MODULE{events = Evts1},
    {keep_state, S2};
login(info, {scard_result, _}, #?MODULE{}) ->
    keep_state_and_data;

login(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

login(info, {_, {focus, Field}}, S0 = #?MODULE{}) ->
    ok = lv_group:focus_obj(Field),
    {keep_state, S0};

login(info, {_, {login, UserText, PwText}}, S0 = #?MODULE{}) ->
    {ok, UserDomain} = lv_textarea:get_text(UserText),
    {ok, Password} = lv_textarea:get_text(PwText),
    {Domain, Username} = split_domain(UserDomain, S0),
    S1 = S0#?MODULE{creds = #{username => Username, password => Password,
                              domain => Domain}},
    {next_state, check_login, S1};

login(info, {_, {login_pin, Slot, PinText}}, S0 = #?MODULE{}) ->
    {ok, Pin} = lv_textarea:get_text(PinText),
    S1 = S0#?MODULE{creds = #{slot => Slot, pin => Pin}},
    {next_state, check_pin, S1}.

challenge_key(Piv, Slot, Key) ->
    Alg = nist_piv:algo_for_key(Key),
    Challenge = <<"rdpivy cak challenge", 0,
        (crypto:strong_rand_bytes(16))/binary>>,
    HashAlgo = case Alg of
        rsa2048 -> sha256;
        eccp256 -> sha256;
        eccp384 -> sha384;
        eccp521 -> sha512
    end,
    Hash = crypto:hash(HashAlgo, Challenge),
    case apdu_transform:command(Piv, {sign, Slot, Alg, Hash}) of
        {ok, [{ok, CardSig}]} ->
            public_key:verify(Challenge, HashAlgo, CardSig, Key);
        Err ->
            lager:debug("error while challenging slot ~s: ~999p", [Slot, Err]),
            false
    end.

scard_disconnect(S0 = #?MODULE{piv = undefined}) ->
    S0;
scard_disconnect(S0 = #?MODULE{piv = Piv, scard = SC0}) ->
    lager:debug("closing scard connection and handle"),
    exit(Piv, kill),
    {ok, SC1} = rdpdr_scard:disconnect(leave, SC0),
    ok = rdpdr_scard:close(SC1),
    S0#?MODULE{piv = undefined, scard = undefined}.

check_pin(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying PIN...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
check_pin(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_pin(state_timeout, check, S0 = #?MODULE{creds = #{pin := <<>>}}) ->
    {next_state, login, S0#?MODULE{errmsg = <<"PIN required">>}};
check_pin(state_timeout, check, S0 = #?MODULE{creds = Creds0, piv = Piv,
                                              cinfo = CInfo, listener = L}) ->
    #{slot := Slot, pin := PIN} = Creds0,
    #{slots := #{piv_card_auth := CAKSlot, Slot := SlotInfo}} = CInfo,
    #{pubkey := CAK} = CAKSlot,
    #{pubkey := PubKey, upn := [UPN | _]} = SlotInfo,
    [Username, _Domain] = string:split(UPN, "@"),
    [DefaultDomain | _] = rdpproxy:config([frontend, L, domains], [<<".">>]),
    Hdl0 = #{user => iolist_to_binary(Username),
             domain => iolist_to_binary(DefaultDomain),
             password => <<>>,
             tgts => #{}},
    Creds1 = Creds0#{username => iolist_to_binary(Username),
                     domain => iolist_to_binary(DefaultDomain)},
    UInfo = #{user => iolist_to_binary(Username), groups => []},
    S1 = S0#?MODULE{hdl = Hdl0, creds = Creds1, uinfo = UInfo},
    ok = apdu_transform:begin_transaction(Piv),
    {ok, [{ok, _}]} = apdu_transform:command(Piv, select),
    case challenge_key(Piv, piv_card_auth, CAK) of
        true ->
            case apdu_transform:command(Piv, {verify_pin, piv_pin, PIN}) of
                {ok, [ok]} ->
                    Screen = make_waiting_screen(
                        "Challenging smartcard key...\n"
                        "(Touch may be required)", S0),
                    case challenge_key(Piv, Slot, PubKey) of
                        true ->
                            apdu_transform:end_transaction(Piv),
                            prometheus_counter:inc(smartcard_auths_total),
                            #?MODULE{srv = {FPid, _}} = S0,
                            conn_ra:annotate(FPid, #{
                                session => Hdl0#{ip => undefined},
                                duo_preauth => <<"bypass">>
                                }),
                            S2 = scard_disconnect(S1#?MODULE{screen = Screen}),
                            {next_state, check_shell, S2};
                        false ->
                            apdu_transform:end_transaction(Piv),
                            prometheus_counter:inc(auth_failures_total),
                            ErrMsg = iolist_to_binary(io_lib:format(
                                "Failed to validate Smartcard PIN (certificate "
                                "verification failure)", [])),
                            {next_state, login, S0#?MODULE{errmsg = ErrMsg}}
                    end;
                {ok, [{error, bad_auth, Attempts}]} ->
                    apdu_transform:end_transaction(Piv),
                    prometheus_counter:inc(auth_failures_total),
                    ErrMsg = iolist_to_binary(io_lib:format(
                        "Failed to validate Smartcard PIN, ~B attempts left",
                        [Attempts])),
                    {next_state, login, S0#?MODULE{errmsg = ErrMsg}};
                Err ->
                    lager:debug("apdu err = ~999p", [Err]),
                    apdu_transform:end_transaction(Piv),
                    ErrMsg = <<"Failed to communicate with smartcard.">>,
                    {next_state, login, S0#?MODULE{errmsg = ErrMsg}}
            end;
        false ->
            apdu_transform:end_transaction(Piv),
            prometheus_counter:inc(auth_failures_total),
            lager:debug("CAK verification failed"),
            {next_state, login, S0#?MODULE{
                errmsg = <<"Failed to validate Smartcard PIN "
                    "(CAK verification failure)">>}}
    end.

check_login(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying login details...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
check_login(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_login(state_timeout, check, S0 = #?MODULE{creds = #{username := <<>>}}) ->
    {next_state, login, S0#?MODULE{errmsg = <<"Username and password required">>}};
check_login(state_timeout, check, S0 = #?MODULE{creds = #{password := <<>>}}) ->
    {next_state, login, S0#?MODULE{errmsg = <<"Username and password required">>}};
check_login(state_timeout, check, S0 = #?MODULE{creds = Creds0, srv = Srv}) ->
    #{username := Username, password := Password, domain := Domain} = Creds0,
    {FPid, _} = Srv,
    Creds1 = Creds0#{session => FPid},

    case krb_auth:authenticate(Creds1) of
        {true, UInfo, Tgts} ->
            lager:debug("auth for ~s succeeded!", [Username]),
            Hdl0 = #{user => Username, domain => Domain, password => Password,
                     tgts => Tgts},
            conn_ra:annotate(FPid, #{
                session => Hdl0#{ip => undefined, password => snip,
                                 tgts => snip},
                duo_preauth => <<"bypass">>
                }),
            S1 = scard_disconnect(S0#?MODULE{hdl = Hdl0, uinfo = UInfo}),
            {next_state, check_mfa, S1};

        false ->
            lager:debug("auth for ~s failed", [Username]),
            prometheus_counter:inc(auth_failures_total),
            {next_state, login, S0#?MODULE{
                errmsg = <<"Invalid username or password.">>}}
    end.

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

check_mfa(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Checking Duo MFA...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, check_bypass}]};
check_mfa(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
check_mfa(state_timeout, check_bypass, S0 = #?MODULE{creds = Creds, uinfo = UInfo0}) ->
    #{username := Username} = Creds,
    #?MODULE{peer = Peer, cinfo = CardInfo, uinfo = UInfo0} = S0,
    UInfo1 = UInfo0#{card_info => CardInfo, client_ip => Peer},
    SkipDuoACL = rdpproxy:config([duo, bypass_acl], [{deny, everybody}]),
    Now = erlang:system_time(second),
    case session_ra:process_rules(UInfo1, Now, SkipDuoACL) of
        allow ->
            lager:debug("duo bypass for ~s", [Username]),
            {next_state, check_shell, S0};
        deny ->
            {keep_state, S0, [{state_timeout, 100, preauth}]}
    end;
check_mfa(state_timeout, preauth, S0 = #?MODULE{creds = Creds, srv = Srv,
                                                duo = Duo, peer = Peer,
                                                duoid = DuoId}) ->
    {FPid, _} = Srv,
    #{username := Username} = Creds,
    Args = #{
        <<"username">> => Username,
        <<"ipaddr">> => Peer,
        <<"trusted_device_token">> => DuoId
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
            {next_state, check_shell, S0};
        {ok, #{<<"result">> := <<"enroll">>}} ->
            S1 = S0#?MODULE{errmsg = <<"Duo MFA required but not enrolled.\n"
                "Visit auth.uq.edu.au in a web browser to set up.">>},
            {next_state, login, S1};
        {ok, #{<<"result">> := <<"allow">>}} ->
            lager:debug("duo bypass for ~p", [Username]),
            {next_state, check_shell, S0};
        {ok, #{<<"result">> := <<"auth">>, <<"devices">> := Devs = [_Dev1 | _]}} ->
            S1 = S0#?MODULE{duodevs = Devs},
            case remember_ra:check({DuoId, Username}) of
                true ->
                    lager:debug("skipping duo for ~p due to remember me", [Username]),
                    {next_state, check_shell, S1};
                false ->
                    lager:debug("sending ~p to duo screen", [Username]),
                    {next_state, mfa_choice, S1}
            end;
        {ok, #{<<"result">> := <<"deny">>, <<"status_msg">> := Msg}} ->
            S1 = S0#?MODULE{errmsg = Msg},
            lager:debug("duo deny for ~p: ~p (id = ~p)", [Username, Msg, DuoId]),
            {next_state, login, S1};
        {error, {error, timeout}} ->
            lager:debug("timed out doing duo preauth, trying again"),
            {keep_state_and_data, [{state_timeout, 100, preauth}]};
        Else ->
            lager:debug("duo preauth else for ~p: ~p (id = ~p)", [Username, Else, DuoId]),
            case remember_ra:check({DuoId, Username}) of
                true ->
                    lager:debug("skipping duo for ~p due to remember me", [Username]),
                    {next_state, check_shell, S0};
                false ->
                    Msg = iolist_to_binary(io_lib:format("Error contacting Duo MFA:\n~p", [Else])),
                    S1 = S0#?MODULE{errmsg = Msg},
                    {next_state, login, S1}
            end
    end.

mfa_choice(enter, _PrevState, S0 = #?MODULE{duodevs = Devs, sty = Sty,
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
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, pressed,
                    {push, Id}),

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
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, pressed,
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
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, pressed,
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
                    {passcode, Id, CodeText, MethodBtn}),
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, pressed,
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
                    {passcode, Id, CodeText, MethodBtn}),
                {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, pressed,
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
    ok = lv_label:set_text(CancelBtnLbl, "Cancel"),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, pressed, cancel),
    Evts1 = [CancelEvt | Evts0],

    %% TODO: add yubikey and u2f devices?

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S1#?MODULE{screen = Screen, events = Evts1,
                            rmbrchk = RememberCheck}};

mfa_choice(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

mfa_choice(info, {_, cancel}, S0 = #?MODULE{}) ->
    #?MODULE{creds = #{username := U}} = S0,
    Creds1 = #{username => U},
    {next_state, login, S0#?MODULE{creds = Creds1}};

mfa_choice(info, {_, {push, DevId}}, S0 = #?MODULE{}) ->
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk} = S0,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    Code = gen_push_code(),
    Creds1 = Creds0#{duo => #{device => DevId, method => push, code => Code,
                              remember_me => RememberMe}},
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, mfa_auth, S1};

mfa_choice(info, {_, {sms_codes, DevId, Btn}}, S0 = #?MODULE{duo = Duo}) ->
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

mfa_choice(info, {_, {call, DevId}}, S0 = #?MODULE{}) ->
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk} = S0,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    Creds1 = Creds0#{duo => #{device => DevId, method => call,
                              remember_me => RememberMe}},
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, mfa_auth, S1};

mfa_choice(info, {_, {passcode, DevId, CodeText, _Btn}}, S0 = #?MODULE{}) ->
    {ok, OTP} = lv_textarea:get_text(CodeText),
    #?MODULE{creds = Creds0, rmbrchk = RmbrChk} = S0,
    {ok, RememberMe} = lv_checkbox:is_checked(RmbrChk),
    Creds1 = Creds0#{duo => #{device => DevId, method => otp, otp => OTP,
                              remember_me => RememberMe}},
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, mfa_auth, S1}.

mfa_auth(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Verifying MFA details...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, check}]};
mfa_auth(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
mfa_auth(state_timeout, check, S0 = #?MODULE{creds = Creds, duo = Duo,
                                             peer = Peer, duoid = DuoId}) ->
    #{username := U, duo := DuoCreds} = Creds,
    RememberMe = maps:get(remember_me, DuoCreds, false),
    case DuoCreds of
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
                    lager:debug("duo denied passcode: ~999p", [R]),
                    S1 = S0#?MODULE{errmsg = "Duo Push denied"},
                    {next_state, mfa_choice, S1};
                {ok, #{<<"result">> := <<"allow">>}} ->
                    {next_state, mfa_push_code, S0#?MODULE{duotx = undefined}};
                {error, {error, timeout}} ->
                    lager:debug("duo auth call timed out, retrying"),
                    {keep_state_and_data, [{state_timeout, 500, check}]};
                Err = {error, _} ->
                    lager:debug("duo auth error: ~999p", [Err]),
                    Msg = io_lib:format("Error contacting Duo API:\n~p", [Err]),
                    S1 = S0#?MODULE{errmsg = Msg},
                    {next_state, mfa_choice, S1};
                {ok, #{<<"txid">> := TxId}} ->
                    {next_state, mfa_push_code, S0#?MODULE{duotx = TxId}}
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
                    {next_state, mfa_choice, S1};
                {ok, #{<<"result">> := <<"allow">>}} ->
                    case RememberMe of
                        false -> ok;
                        true -> ok = remember_ra:remember({DuoId, U})
                    end,
                    {next_state, check_shell, S0};
                Err = {error, _} ->
                    lager:debug("duo auth error: ~999p", [Err]),
                    S1 = S0#?MODULE{errmsg = "Error contacting Duo API"},
                    {next_state, mfa_choice, S1};
                {ok, #{<<"txid">> := TxId}} ->
                    {next_state, mfa_async, S0#?MODULE{duotx = TxId}}
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
                    {next_state, mfa_choice, S1};
                {ok, #{<<"result">> := <<"allow">>}} ->
                    case RememberMe of
                        false -> ok;
                        true -> ok = remember_ra:remember({DuoId, U})
                    end,
                    {next_state, check_shell, S0};
                {error, {error, timeout}} ->
                    lager:debug("duo auth call timed out, retrying"),
                    {keep_state_and_data, [{state_timeout, 500, check}]};
                Err = {error, _} ->
                    lager:debug("duo auth error: ~999p", [Err]),
                    S1 = S0#?MODULE{errmsg = "Error contacting Duo API"},
                    {next_state, mfa_choice, S1}
            end
    end.

mfa_async(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Waiting for Duo...", S0),
    {ok, CancelBtn} = lv_btn:create(Screen),
    {ok, BtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(BtnLbl, "Cancel"),
    {ok, BtnEvt, _} = lv_event:setup(CancelBtn, pressed, cancel),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen, events = [BtnEvt]},
        [{state_timeout, 500, check}]};
mfa_async(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
mfa_async(state_timeout, check, S0 = #?MODULE{duo = Duo, duotx = TxId}) ->
    #?MODULE{creds = #{username := U, duo := DuoCreds}} = S0,
    RememberMe = maps:get(remember_me, DuoCreds, false),
    case duo:auth_status(Duo, TxId) of
        {ok, #{<<"result">> := <<"waiting">>}} ->
            {keep_state, S0, [{state_timeout, 1000, check}]};
        {ok, #{<<"result">> := <<"deny">>, <<"status_msg">> := StatusMsg}} ->
            S1 = S0#?MODULE{errmsg = ["Duo MFA denied: ", StatusMsg]},
            {next_state, mfa_choice, S1};
        {ok, #{<<"result">> := <<"deny">>}} ->
            S1 = S0#?MODULE{errmsg = "Duo MFA denied"},
            {next_state, mfa_choice, S1};
        {ok, #{<<"result">> := <<"allow">>}} ->
            lager:debug("duo allowed auth, proceeding"),
            #?MODULE{duoid = DuoId} = S0,
            case RememberMe of
                false -> ok;
                true -> ok = remember_ra:remember({DuoId, U})
            end,
            {next_state, check_shell, S0};
        _ ->
            {keep_state, S0, [{state_timeout, 1000, check}]}
    end;
mfa_async(info, {_, cancel}, S0 = #?MODULE{}) ->
    % start a new duo client on cancel, to make sure it doesn't get stuck
    {ok, Duo} = duo:start_link(),
    S1 = S0#?MODULE{errmsg = "Cancelled", duo = Duo},
    {next_state, mfa_choice, S1}.

mfa_push_code(enter, _PrevState, S0 = #?MODULE{sty = Sty, inst = Inst}) ->
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
        " - Check for a 4-digit code before accepting the Push.\n - Enter "
        "the code below, then press Accept on your device.\n"]),
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
        {code, CodeText}),
    {ok, MethodBtnEvt, _} = lv_event:setup(MethodBtn, pressed,
        {code, CodeText}),

    {ok, CancelBtn} = lv_btn:create(Flex),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(CancelBtnLbl, "Cancel"),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, pressed, cancel),

    Evts = [CodeInpEvt, MethodBtnEvt, CancelEvt],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts}};

mfa_push_code(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

mfa_push_code(info, {_, {code, CodeText}}, S0 = #?MODULE{creds = Creds}) ->
    #?MODULE{duotx = DuoTx} = S0,
    #{duo := #{method := push, code := WantCode}} = Creds,
    {ok, Code} = lv_textarea:get_text(CodeText),
    case {Code, DuoTx} of
        {WantCode, undefined} ->
            {next_state, check_shell, S0};
        {WantCode, _} ->
            {next_state, mfa_async, S0};
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

mfa_push_code(info, {_, cancel}, S0 = #?MODULE{creds = Creds0}) ->
    Creds1 = maps:remove(duo, Creds0),
    S1 = S0#?MODULE{creds = Creds1},
    {next_state, mfa_choice, S1}.

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
                    #?MODULE{creds = Creds0, hdl = Hdl0} = S0,
                    Creds1 = case lists:member(no_forward_creds, Opts) of
                        true ->
                            maps:remove(tgts, maps:remove(password, Creds0));
                        false ->
                            Creds0
                    end,
                    Hdl1 = case lists:member(no_forward_creds, Opts) of
                        true -> Hdl0#{password => <<>>};
                        false -> Hdl0
                    end,
                    S1 = S0#?MODULE{creds = Creds1, hdl = Hdl1,
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
    {ok, BtnEvt, _} = lv_event:setup(CancelBtn, pressed, cancel),

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
                {[Dev | _], _} ->
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
manual_host(info, {_, cancel}, S0 = #?MODULE{rstate = RState}) ->
    {next_state, RState, S0}.

process_acl(ConfigName, #?MODULE{creds = Creds, uinfo = UInfo0,
                                 cinfo = CInfo, peer = ClientIP}) ->
    ACL = rdpproxy:config([ui, ConfigName], [{deny, everybody}]),
    Now = erlang:system_time(second),
    % Always include the client IP as well as the basic user info from KRB5
    UInfo1 = UInfo0#{client_ip => ClientIP},
    % Only include the card_info if we used smartcard auth
    UInfo2 = case Creds of
        #{slot := _, pin := _} -> UInfo1#{card_info => CInfo};
        _ -> UInfo1
    end,
    lager:debug("~999p: ~999p", [UInfo2, ACL]),
    session_ra:process_rules(UInfo2, Now, ACL).

pool_choice(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Loading pool list...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 100, check}]};
pool_choice(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
pool_choice(state_timeout, check, S0 = #?MODULE{uinfo = UInfo, sty = Sty,
                                                inst = Inst}) ->
    #{title := TitleStyle, instruction := InstrStyle} = Sty,

    {ok, Pools} = session_ra:get_pools_for(UInfo),

    ShowAdmin = (process_acl(admin_acl, S0) =:= allow),
    ShowNMSPool = ShowAdmin orelse (process_acl(pool_nms_acl, S0) =:= allow),

    case Pools of
        [#{id := ID}] when (not ShowNMSPool) ->
            {next_state, pool_host_choice, S0#?MODULE{pool = ID}};

        _ ->
            {Screen, Flex} = make_screen(S0),
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
                    {ok, NmsOpt} = lv_list:add_btn(List, home, "NMS"),
                    {ok, NmsSubLbl} = lv_label:create(NmsOpt),
                    ok = lv_label:set_text(NmsSubLbl,
                        "Choose from personally-assigned hosts in EAIT NMS."),
                    ok = lv_obj:set_size(NmsSubLbl, {{percent, 60}, content}),
                    ok = lv_group:add_obj(InpGroup, NmsOpt),
                    {ok, NmsEvt, _} = lv_event:setup(NmsOpt, pressed, nms_choice),
                    [NmsEvt];
                false ->
                    []
            end,

            {ok, _} = lv_list:add_text(List, "Available pools"),
            Evts1 = lists:foldl(fun (PoolInfo, Acc) ->
                #{id := ID, title := PoolTitle, help_text := HelpText} = PoolInfo,
                {ok, PoolOpt} = lv_list:add_btn(List, right, PoolTitle),
                {ok, PoolSubLbl} = lv_label:create(PoolOpt),
                ok = lv_label:set_text(PoolSubLbl, HelpText),
                ok = lv_obj:set_size(PoolSubLbl, {{percent, 60}, content}),
                ok = lv_group:add_obj(InpGroup, PoolOpt),
                {ok, PoolEvt, _} = lv_event:setup(PoolOpt, pressed, {pool, ID}),
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
    #?MODULE{inst = Inst} = S0,
    #{item_title := ItemTitleStyle, title := TitleStyle,
      instruction := InstrStyle, role := RoleStyle} = Sty,

    {Screen, Flex} = make_screen(S0),
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

    {ok, List} = lv_list:create(Flex),
    ok = lv_obj:set_size(List, {{percent, 100}, content}),
    ok = lv_obj:set_style_max_height(List, {percent, 70}),

    Evts0 = lists:foldl(fun (Dev, Acc) ->
        #{ip := IP, role := Role, last_alloc := LastAlloc} = Dev,
        Desc = maps:get(desc, Dev, none),
        Hostname = maps:get(hostname, Dev, IP),
        {ok, Opt} = lv_list:add_btn(List, none, none),

        {ok, Icon} = lv_label:create(Opt),
        ok = lv_obj:set_style_text_font(Icon, {"lineawesome", regular, 16}),
        ok = lv_label:set_text(Icon, unicode:characters_to_binary([16#f108], utf8)),
        ok = lv_obj:set_size(Icon, {{percent, 3}, content}),

        {ok, Label} = lv_span:create(Opt),
        ok = lv_obj:add_flag(Label, clickable),
        ok = lv_obj:set_size(Label, {{percent, 39}, content}),
        ok = lv_span:set_mode(Label, break),

        {ok, DevTitle} = lv_span:new_span(Label),
        ok = lv_span:set_style(DevTitle, ItemTitleStyle),
        ok = lv_span:set_text(DevTitle, Hostname),

        case Desc of
            none -> ok;
            <<>> -> ok;
            _ ->
                {ok, DescSpan} = lv_span:new_span(Label),
                ok = lv_span:set_text(DescSpan, [$\n, Desc]),
                ok = lv_span:set_style(DescSpan, RoleStyle)
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
        ok = lv_obj:set_size(IPLabel, {{percent, 26}, content}),
        ok = lv_label:set_text(IPLabel, IP),
        ok = lv_obj:add_style(IPLabel, RoleStyle),

        case Dev of
            #{busy := true} ->
                ok = lv_obj:add_state(Opt, disabled),
                ok = lv_obj:set_style_opa(Opt, 0.8),
                Acc;
            _ ->
                ok = lv_group:add_obj(InpGroup, Opt),
                {ok, DevEvt, _} = lv_event:setup(Opt, pressed,
                    {select_host, IP}),
                [DevEvt | Acc]
        end
    end, [], Devs),

    {ok, CancelBtn} = lv_btn:create(Flex),
    {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
    ok = lv_label:set_text(CancelBtnLbl, "Back"),
    {ok, CancelEvt, _} = lv_event:setup(CancelBtn, pressed, cancel),
    Evts1 = [CancelEvt | Evts0],

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts1}};

pool_host_choice(info, {_, cancel}, S0 = #?MODULE{}) ->
    {next_state, pool_choice, S0};
pool_host_choice(info, {_, {select_host, IP}}, S0 = #?MODULE{hdl = Hdl0}) ->
    Hdl1 = Hdl0#{ip => IP},
    {next_state, alloc_handle, S0#?MODULE{hdl = Hdl1}}.

nms_choice(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Loading computer list from NMS...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, check}]};
nms_choice(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
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
      role := RoleStyle} = Sty,
    #{username := U} = Creds,

    Now = erlang:system_time(second),
    Devs1 = lists:map(fun (Dev0) ->
        #{ip := IP} = Dev0,
        Dev1 = case session_ra:get_host(IP) of
            {ok, #{role := Role, alloc_history := AQ}} ->
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
                Dev0#{role => RoleBin, last_alloc => LastAlloc};
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

    {Screen, Flex} = make_screen(S0),
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

    case Devs1 of
        [] ->
            EmptyGrp = make_plain_group(Flex, S0),
            {ok, EmptyText} = lv_span:create(EmptyGrp),
            ok = lv_obj:set_size(EmptyText, {{percent, 80}, content}),
            ok = lv_span:set_mode(EmptyText, break),

            {ok, EmptySpan} = lv_span:new_span(EmptyText),
            ok = lv_span:set_text(EmptySpan, get_msg(no_machines, S0));
        _ ->
            ok
    end,

    {ok, List} = lv_list:create(Flex),
    ok = lv_obj:set_size(List, {{percent, 100}, content}),
    ok = lv_obj:set_style_max_height(List, {percent, 70}),

    Groups = [recent | (maps:keys(Grouped) -- [recent])],

    Evts0 = lists:foldl(fun (GroupKey, Acc) ->
        #{GroupKey := GroupDevs} = Grouped,
        GroupHeading = case GroupKey of
            recent -> "Recently used (last 4w)";
            _ -> GroupKey
        end,
        case GroupDevs of
            [] -> ok;
            _ -> {ok, _} = lv_list:add_text(List, GroupHeading)
        end,
        lists:foldl(fun (Dev, AccAcc) ->
            #{ip := IP, hostname := Hostname, building := Building,
              room := Room, owner := Owner} = Dev,
            DevIcon = case Owner of
                U -> 16#f108;
                _ -> 16#f233
            end,
            Role = maps:get(role, Dev, none),
            {ok, Opt} = lv_list:add_btn(List, none, none),

            {ok, Icon} = lv_label:create(Opt),
            ok = lv_obj:set_style_text_font(Icon, {"lineawesome", regular, 16}),
            ok = lv_label:set_text(Icon, unicode:characters_to_binary([DevIcon], utf8)),
            ok = lv_obj:align(Icon, left_mid),
            ok = lv_obj:set_size(Icon, {{percent, 2}, content}),

            {ok, Label} = lv_span:create(Opt),
            ok = lv_obj:add_flag(Label, [clickable, event_bubble]),
            ok = lv_obj:set_size(Label, {{percent, 44}, content}),
            ok = lv_span:set_mode(Label, break),

            case binary:split(Hostname, <<".">>) of
                [HostPre, HostPost] ->
                    {ok, DevTitlePre} = lv_span:new_span(Label),
                    ok = lv_span:set_style(DevTitlePre, ItemTitleStyle),
                    ok = lv_span:set_text(DevTitlePre, HostPre),
                    {ok, DevTitlePost} = lv_span:new_span(Label),
                    ok = lv_span:set_style(DevTitlePost, ItemTitleFadedStyle),
                    ok = lv_span:set_text(DevTitlePost, [$., HostPost]);
                [_] ->
                    {ok, DevTitle} = lv_span:new_span(Label),
                    ok = lv_span:set_style(DevTitle, ItemTitleStyle),
                    ok = lv_span:set_text(DevTitle, Hostname)
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
            ok = lv_obj:set_size(IPLabel, {{percent, 22}, content}),
            ok = lv_label:set_text(IPLabel, IP),
            ok = lv_obj:add_style(IPLabel, RoleStyle),

            ok = lv_group:add_obj(InpGroup, Opt),
            {ok, DevEvt, _} = lv_event:setup(Opt, pressed,
                {select_host, Dev}),
            [DevEvt | AccAcc]
        end, Acc, GroupDevs)
    end, [], Groups),

    Mode = rdpproxy:config([frontend, L, mode], pool),
    Evts1 = case Mode of
        nms_choice ->
            Evts0;
        _ ->
            {ok, CancelBtn} = lv_btn:create(Flex),
            {ok, CancelBtnLbl} = lv_label:create(CancelBtn),
            ok = lv_label:set_text(CancelBtnLbl, "Back"),
            {ok, CancelEvt, _} = lv_event:setup(CancelBtn, pressed, cancel),
            [CancelEvt | Evts0]
    end,

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 50, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S0#?MODULE{screen = Screen, events = Evts1}};

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

nms_choice(info, {_, cancel}, S0 = #?MODULE{}) ->
    {next_state, check_shell, S0}.

alloc_handle(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Allocating handle...", S0),
    do_ping_annotate(S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 200, start}]};
alloc_handle(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};
alloc_handle(state_timeout, start, S0 = #?MODULE{pool = Pool, hdl = Hdl}) ->
    T0 = erlang:system_time(millisecond),
    {ok, AllocPid} = host_alloc_fsm:start(Pool, Hdl),
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
    {ok, BtnEvt, _} = lv_event:setup(CancelBtn, pressed, cancel),

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
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 500, redir}]};

redir(info, {'DOWN', MRef, process, _, _}, S0 = #?MODULE{mref = MRef}) ->
    {stop, normal, S0};

redir(state_timeout, redir, #?MODULE{srv = Srv, hdl = Hdl, listener = L}) ->
    #{handle := Cookie, sessid := SessId} = Hdl,
    lager:debug("sending ts_redir"),
    rdp_server:send_redirect(Srv, Cookie, SessId,
        rdpproxy:config([frontend, L, hostname], <<"localhost">>)),
    {keep_state_and_data, [{state_timeout, 500, close}]};

redir(state_timeout, close, S0 = #?MODULE{}) ->
    {stop, normal, S0}.

-if(0).

startup(timeout, S = #?MODULE{frontend = F, listener = L}) ->
    {W, H, Bpp} = rdp_server:get_canvas(F),
    Format = case Bpp of
        24 -> rgb24;
        16 -> rgb16_565;
        _ -> error({bad_bpp, Bpp})
    end,
    {PeerIp, _PeerPort} = rdp_server:get_peer(F),

    Caps = rdp_server:get_caps(F),
    GeneralCap = lists:keyfind(ts_cap_general, 1, Caps),

    Tsuds = rdp_server:get_tsuds(F),
    TsudCore = lists:keyfind(tsud_core, 1, Tsuds),
    #tsud_net{channels = Chans} = lists:keyfind(tsud_net, 1, Tsuds),
    ChanNames = [Name || #tsud_net_channel{name = Name} <- Chans],

    [OSType, OSSubType] = GeneralCap#ts_cap_general.os,
    OS = iolist_to_binary(io_lib:format("~p/~p", [OSType, OSSubType])),
    prometheus_counter:inc(rdp_connections_client_os_build_total,
        [OS, TsudCore#tsud_core.client_build]),

    TSInfo = rdp_server:get_ts_info(F),
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

    S2 = S#?MODULE{w = float(W), h = float(H), bpp = Bpp, format = Format,
                   tsudcore = TsudCore, duoid = DuoId,
                   peer = list_to_binary(inet:ntoa(PeerIp))},
    lager:debug("starting session ~px~p @~p bpp (format ~p)", [W, H, Bpp, Format]),
    case rdp_server:get_redir_support(F) of
        false ->
            lager:debug("redir not supported, presenting error screen"),
            no_redir(setup_ui, S2);
        true ->

    end.

no_redir(setup_ui, S = #?MODULE{w = W, h = H, format = Fmt}) ->
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    TopMod = case (H > W) of
        true -> ui_vlayout;
        false -> ui_hlayout
    end,
    {Msg, MsgLines} = get_msg(msg_noredir, S),
    Events = [
        { [{id, root}],     {set_bgcolor, BgColour} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = TopMod}} },
        { [{id, hlayout}],  init },
        { [{id, hlayout}],  {set_margin, 100} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = logo,
                                     mod = ui_image}} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = loginlyt,
                                     mod = ui_vlayout,
                                     size = {400.0, H}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = banner,
                                     mod = ui_label,
                                     size = {400.0, 38.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = subtitle,
                                     mod = ui_label,
                                     size = {400.0, 20.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = explain,
                                     mod = ui_label,
                                     size = {400.0, 18.0*MsgLines}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = closebtn,
                                     mod = ui_button,
                                     size = {120.0, 40.0}}} },

        { [{id, logo}],         {init, logopath()} },
        { [{id, banner}],       {init, left, rdpproxy:config([ui, title_noredir])} },
        { [{id, banner}],       {set_bgcolor, BgColour} },
        { [{id, subtitle}],       {init, left, rdpproxy:config([ui, subtitle_noredir])} },
        { [{id, subtitle}],       {set_bgcolor, BgColour} },
        { [{id, explain}],      {init, left, Msg} },
        { [{id, explain}],      {set_bgcolor, BgColour} },
        { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(S, Orders),
    {next_state, no_redir, S#?MODULE{root = Root2}};

no_redir({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(no_redir, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            lager:debug("user hit escape"),
            rdp_server:close(F),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(no_redir, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(no_redir, S, [Event]);
        #ts_inpevt_unicode{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(no_redir, S, [Event]);
        _ ->
            {next_state, no_redir, S}
    end;

no_redir({ui, {clicked, closebtn}}, S = #?MODULE{frontend = F}) ->
    lager:debug("user clicked closebtn"),
    rdp_server:close(F),
    {stop, normal, S}.

login(setup_ui, S = #?MODULE{frontend = F, w = W, h = H, format = Fmt}) ->
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    {TopMod, LH} = case (H > W) of
        true -> {ui_vlayout, 250};
        false -> {ui_hlayout, H}
    end,
    Events = [
        { [{id, root}],     {set_bgcolor, BgColour} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = TopMod}} },
        { [{id, hlayout}],  init },
        { [{id, hlayout}],  {set_halign, center} },
        { [{id, hlayout}],  {set_margin, 100} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = logo,
                                     mod = ui_image}} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = loginlyt,
                                     mod = ui_vlayout,
                                     size = {460.0, LH}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = banner,
                                     mod = ui_label,
                                     size = {400.0, 38.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = subbanner,
                                     mod = ui_label,
                                     size = {400.0, 28.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = instru,
                                     mod = ui_label,
                                     size = {400.0, 15.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = userinp,
                                     mod = ui_textinput,
                                     size = {400.0, 30.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = passinp,
                                     mod = ui_textinput,
                                     size = {400.0, 30.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = loginbtn,
                                     mod = ui_button,
                                     size = {120.0, 40.0}}} },

        { [{id, logo}],         {init, logopath()} },
        { [{id, banner}],       {init, left, rdpproxy:config([ui, title_login])} },
        { [{id, banner}],       {set_bgcolor, BgColour} },
        { [{id, subbanner}],    {init, left, rdpproxy:config([ui, subtitle_login])} },
        { [{id, subbanner}],    {set_bgcolor, BgColour} },
        { [{id, instru}],       {init, left, rdpproxy:config([ui, instruction_login])} },
        { [{id, instru}],       {set_bgcolor, BgColour} },
        { [{id, userinp}],      {init, <<"Username">>} },
        { [{id, passinp}],      {init, <<"Password">>, <<"•"/utf8>>} },
        { [{id, loginbtn}],     {init, <<"Login", 0>>} },
        { [{id, userinp}],      focus }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(S, Orders),

    {_Autologon, U, _D, P} = rdp_server:get_autologon(F),
    Events2 = [
        { [{id, userinp}], {set_text, U} },
        { [{id, passinp}], {set_text, P} }
    ] ++ if (byte_size(U) > 0) ->
        [ { [{id, passinp}], focus } ];
    true -> []
    end,

    Tsuds = rdp_server:get_tsuds(F),
    #tsud_core{kbd_layout = KL} = lists:keyfind(tsud_core, 1, Tsuds),
    Events3 = case KL of
        1033 -> Events2;
        _ ->
            Events2 ++ [
                { [{id, loginlyt}], {add_child,
                                     #widget{id = kbdwarn,
                                             mod = ui_label,
                                             size = {400.0, 15.0}}} },
                { [{id, kbdwarn}], {init, center, <<"Warning: keyboard layout "
                    "not supported; using English/US">>} },
                { [{id, kbdwarn}], {set_bgcolor, BgColour} }
            ]
    end,

    {Root3, Orders2, []} = ui:handle_events(Root2, Events3),
    send_orders(S, Orders2),

    S2 = S#?MODULE{root = Root3},

    if
        (byte_size(U) > 0) andalso (byte_size(P) > 0) ->
            login(check_creds, S2);
        true ->
            {next_state, login, S2}
    end;

login({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            lager:debug("user hit escape"),
            rdp_server:close(F),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_key{code = caps} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_sync{} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_unicode{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(login, S, [Event]);
        #ts_suppress_output{allow_updates = false} ->
            {next_state, login, S};
        #ts_suppress_output{allow_updates = true} ->
            Event = { [{id, root}], redraw },
            handle_root_events(login, S, [Event]);
        #ts_refresh_rect{} ->
            Event = { [{id, root}], redraw },
            handle_root_events(login, S, [Event]);
        _ ->
            {next_state, login, S}
    end;

login({ui, {paste, TextInpId}}, S = #?MODULE{}) ->
    handle_paste(TextInpId, login, S);

login({ui, {submitted, userinp}}, S = #?MODULE{}) ->
    Event = { [{id, passinp}], focus },
    handle_root_events(login, S, [Event]);

login({ui, {submitted, passinp}}, S = #?MODULE{}) ->
    login(check_creds, S);

login({ui, {clicked, loginbtn}}, S = #?MODULE{}) ->
    login(check_creds, S);

login(check_creds, S = #?MODULE{root = Root, listener = L, frontend = {FPid,_}}) ->
    [DefaultDomain | _] = ValidDomains = rdpproxy:config([frontend, L, domains], [<<".">>]),

    [UsernameTxt] = ui:select(Root, [{id, userinp}]),
    UserDomain = ui_textinput:get_text(UsernameTxt),
    {Domain, Username} = case binary:split(UserDomain, <<$\\>>) of
        [D, U] -> case lists:member(D, ValidDomains) of
            true -> {D, U};
            false -> {DefaultDomain, U}
        end;
        [U] -> {DefaultDomain, U}
    end,

    do_ping_annotate(S),

    [PasswordTxt] = ui:select(Root, [{id, passinp}]),
    Password = ui_textinput:get_text(PasswordTxt),

    case {Username, Password} of
        {<<>>, _} ->
            lager:debug("supplied empty username, rejecting"),
            login(invalid_login, S);
        {_, <<>>} ->
            lager:debug("supplied empty password for ~p, rejecting", [Username]),
            login(invalid_login, S);
        _ ->
            UsernameBin = iolist_to_binary([Username]),
            Creds = #{
                session => FPid,
                username => UsernameBin,
                password => iolist_to_binary([Password])
            },
            Fsm = self(),
            spawn(fun() ->
                Res = check_scard(S),
            Fsm ! {scard_result, Res}
            end),
            CardInfo = receive
                {scard_result, {ok, _Piv, _Rdr, SC0, Info}} ->
                    % for now just disconnect, we only check the CAK
                    {ok, SC1} = rdpdr_scard:disconnect(leave, SC0),
                    rdpdr_scard:close(SC1),
                    conn_ra:annotate(FPid, #{scard => Info}),
                    Info;
                {scard_result, _} ->
                    #{slots => #{}}
            after 5000 ->
                #{slots => #{}}
            end,
            case krb_auth:authenticate(Creds) of
                {true, UInfo, Tgts} ->
                    lager:debug("auth for ~p succeeded!", [Username]),
                    Sess0 = #{user => Username, domain => Domain,
                        password => Password, tgts => Tgts},
                    conn_ra:annotate(FPid, #{
                        session => Sess0#{ip => undefined, password => snip,
                                          tgts => snip},
                        duo_preauth => <<"bypass">>}),
                    S1 = S#?MODULE{sess = Sess0, uinfo = UInfo},
                    #?MODULE{peer = Peer} = S1,
                    UInfo2 = UInfo#{card_info => CardInfo,
                                    client_ip => Peer},
                    SkipDuoACL = rdpproxy:config([duo, bypass_acl],
                        [{deny, everybody}]),
                    Now = erlang:system_time(second),
                    case session_ra:process_rules(UInfo2, Now, SkipDuoACL) of
                        allow ->
                            lager:debug("duo bypass for ~p", [Username]),
                            mfa(allow, S1);
                        deny ->
                            login(mfa_start, S1)
                    end;
                false ->
                    lager:debug("auth for ~p failed", [Username]),
                    prometheus_counter:inc(auth_failures_total),
                    login(invalid_login, S)
            end
    end;

login(invalid_login, S = #?MODULE{}) ->
    BgColour = bgcolour(),
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"Invalid username or password">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, BgColour} }
    ],
    handle_root_events(login, S, Events);

login(mfa_deny, S = #?MODULE{duomsg = DuoMsg}) ->
    BgColour = bgcolour(),
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 30.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"Duo MFA denied access:\n", DuoMsg/binary>>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, BgColour} }
    ],
    handle_root_events(login, S, Events);

login(mfa_enroll, S = #?MODULE{}) ->
    BgColour = bgcolour(),
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"Duo MFA required but not enrolled">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, BgColour} }
    ],
    handle_root_events(login, S, Events);

login(mfa_start, S1 = #?MODULE{}) ->
    #?MODULE{duoid = DuoId, duo = Duo, peer = Peer, sess = Sess, uinfo = UInfo,
             frontend = {FPid,_}} = S1,
    #{username := Username} = Sess,
    Args = #{
        <<"username">> => Username,
        <<"ipaddr">> => Peer,
        <<"trusted_device_token">> => DuoId
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
            mfa(allow, S1);
        {ok, #{<<"result">> := <<"enroll">>}} ->
            login(mfa_enroll, S1);
        {ok, #{<<"result">> := <<"allow">>}} ->
            lager:debug("duo bypass for ~p", [Username]),
            mfa(allow, S1);
        {ok, #{<<"result">> := <<"auth">>, <<"devices">> := Devs = [_Dev1 | _]}} ->
            case remember_ra:check({DuoId, Username}) of
                true ->
                    lager:debug("skipping duo for ~p due to remember me", [Username]),
                    mfa(allow, S1);
                false ->
                    lager:debug("sending ~p to duo screen", [Username]),
                    mfa(setup_ui, S1#?MODULE{duodevs = Devs})
            end;
        {ok, #{<<"result">> := <<"deny">>, <<"status_msg">> := Msg}} ->
            S2 = S1#?MODULE{duomsg = Msg},
            lager:debug("duo deny for ~p: ~p (id = ~p)", [Username, Msg, DuoId]),
            login(mfa_deny, S2);
        Else ->
            lager:debug("duo preauth else for ~p: ~p (id = ~p)", [Username, Else, DuoId]),
            case remember_ra:check({DuoId, Username}) of
                true ->
                    lager:debug("skipping duo for ~p due to remember me", [Username]),
                    mfa(allow, S1);
                false ->
                    Msg = iolist_to_binary(io_lib:format("~999p", [Else])),
                    S2 = S1#?MODULE{duomsg = Msg},
                    login(mfa_deny, S2)
            end
    end.

mfa(setup_ui, S = #?MODULE{w = W, h = H, format = Fmt}) ->
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    {TopMod, LH} = case (H > W) of
        true -> {ui_vlayout, 2 * (H / 3)};
        false -> {ui_hlayout, H}
    end,
    DuoDevs = S#?MODULE.duodevs,
    Events0 = [
        { [{id, root}],     {set_bgcolor, BgColour} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = TopMod}} },
        { [{id, hlayout}],  init },
        { [{id, hlayout}],  {set_halign, center} },
        { [{id, hlayout}],  {set_margin, 100} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = logo,
                                     mod = ui_image}} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = loginlyt,
                                     mod = ui_vlayout,
                                     size = {460.0, LH}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = subbanner,
                                     mod = ui_label,
                                     size = {400.0, 36.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = instru,
                                     mod = ui_label,
                                     size = {400.0, 30.0}}} },

        { [{id, logo}],         {init, logopath()} },
        { [{id, subbanner}],    {init, left, rdpproxy:config([ui, title_mfa])} },
        { [{id, subbanner}],    {set_bgcolor, BgColour} },
        { [{id, instru}],       {init, left, rdpproxy:config([ui, instruction_mfa])} },
        { [{id, instru}],       {set_bgcolor, BgColour} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events0),
    send_orders(S, Orders),

    Events1 = lists:foldl(fun (Dev, Acc) ->
        #{<<"device">> := Id, <<"type">> := Type} = Dev,
        Name = case Dev of
            #{<<"display_name">> := N} -> N;
            #{<<"name">> := N} -> N;
            #{<<"device">> := N} -> N
        end,
        Caps = case Dev of
            #{<<"capabilities">> := C} -> C;
            #{<<"type">> := <<"token">>} -> [<<"mobile_otp">>];
            #{<<"type">> := <<"phone">>} -> [<<"push">>, <<"sms">>, <<"phone">>, <<"mobile_otp">>]
        end,
        Acc1 = case Caps of
            [] -> Acc;
            _ -> Acc ++ [
                { [{id, loginlyt}],     {add_child,
                                         #widget{id = {devlyt, Id},
                                                 mod = ui_hlayout,
                                                 size = {440.0, 150.0}}} },
                { [{id, {devlyt, Id}}],  init },

                { [{id, {devlyt, Id}}], {add_child,
                                         #widget{id = {devlbllyt, Id},
                                                 mod = ui_vlayout,
                                                 size = {230.0, 150.0}}} },
                { [{id, {devlbllyt, Id}}], init },

                { [{id, {devlbllyt, Id}}],  {add_child,
                                          #widget{id = {devlbl, Id},
                                                  mod = ui_label,
                                                  size = {220.0, 17.0}}} },
                { [{id, {devlbl, Id}}],  {init, left, Name} },
                { [{id, {devlbl, Id}}],  {set_bgcolor, BgColour} },
                { [{id, {devlbllyt, Id}}],  {add_child,
                                          #widget{id = {devtlbl, Id},
                                                  mod = ui_label,
                                                  size = {220.0, 15.0}}} },
                { [{id, {devtlbl, Id}}],  {init, left, Type} },
                { [{id, {devtlbl, Id}}],  {set_bgcolor, BgColour} },

                { [{id, {devlyt, Id}}],  {add_child,
                                          #widget{id = {devbtnslyt, Id},
                                                  mod = ui_vlayout,
                                                  size = {180.0, 150.0}}} },
                { [{id, {devbtnslyt, Id}}], init }
            ]
        end,
        Acc2 = case lists:member(<<"push">>, Caps) of
            true ->
                Acc1 ++ [
                    { [{id, {devbtnslyt, Id}}], {add_child,
                                                 #widget{id = {pushbtn, Id},
                                                         mod = ui_button,
                                                         size = {140.0, 30.0}}} },
                    { [{id, {pushbtn, Id}}],  {init, <<"Duo Push", 0>>} }
                ];
            false -> Acc1
        end,
        Acc3 = case lists:member(<<"sms">>, Caps) of
            true ->
                Acc2 ++ [
                    { [{id, {devbtnslyt, Id}}], {add_child,
                                                 #widget{id = {smsbtn, Id},
                                                         mod = ui_button,
                                                         size = {140.0, 30.0}}} },
                    { [{id, {smsbtn, Id}}],  {init, <<"SMS code", 0>>} }
                ];
            false -> Acc2
        end,
        Acc4 = case lists:member(<<"phone">>, Caps) of
            true ->
                Acc3 ++ [
                    { [{id, {devbtnslyt, Id}}], {add_child,
                                                 #widget{id = {callbtn, Id},
                                                         mod = ui_button,
                                                         size = {140.0, 30.0}}} },
                    { [{id, {callbtn, Id}}],  {init, <<"Phonecall", 0>>} }
                ];
            false -> Acc3
        end,
        _Acc5 = case lists:member(<<"mobile_otp">>, Caps) of
            true ->
                Acc4 ++ [
                    { [{id, {devbtnslyt, Id}}], {add_child,
                                                 #widget{id = {otplyt, Id},
                                                         mod = ui_hlayout,
                                                         size = {140.0, 30.0}}} },
                    { [{id, {otplyt, Id}}],      init },
                    { [{id, {otplyt, Id}}],  {set_margin, 0} },
                    { [{id, {otplyt, Id}}], {add_child,
                                                 #widget{id = {otpinp, Id},
                                                         mod = ui_textinput,
                                                         size = {100.0, 28.0}}} },
                    { [{id, {otpinp, Id}}],  {init, <<"code">>} },
                    { [{id, {otplyt, Id}}], {add_child,
                                                 #widget{id = {otpbtn, Id},
                                                         mod = ui_button,
                                                         size = {28.0, 28.0}}} },
                    { [{id, {otpbtn, Id}}],  {init, <<"OK", 0>>} }
                ];
            false -> Acc4
        end
    end, [], DuoDevs),

    Events2 = Events1 ++ [
        { [{id, loginlyt}], {add_child,
                             #widget{id = rmbrchk,
                                     mod = ui_checkbox,
                                     size = {300.0, 18.0}}} },
        { [{id, rmbrchk}],       {init, left, <<"Remember this computer for 10hr">>} },
        { [{id, rmbrchk}],       {set_bgcolor, BgColour} }
    ],
    {Root3, Orders2, []} = ui:handle_events(Root2, Events2),
    send_orders(S, Orders2),

    {next_state, mfa, S#?MODULE{root = Root3}};

mfa({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(mfa, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            lager:debug("user hit escape"),
            rdp_server:close(F),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(mfa, S, [Event]);
        #ts_inpevt_key{code = caps} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(mfa, S, [Event]);
        #ts_inpevt_sync{} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(mfa, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(mfa, S, [Event]);
        #ts_inpevt_unicode{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(mfa, S, [Event]);
        #ts_suppress_output{allow_updates = false} ->
            {next_state, mfa, S};
        #ts_suppress_output{allow_updates = true} ->
            Event = { [{id, root}], redraw },
            handle_root_events(mfa, S, [Event]);
        #ts_refresh_rect{} ->
            Event = { [{id, root}], redraw },
            handle_root_events(mfa, S, [Event]);
        _ ->
            {next_state, mfa, S}
    end;

mfa({ui, {paste, TextInpId}}, S = #?MODULE{}) ->
    handle_paste(TextInpId, mfa, S);

mfa({ui, {submitted, {otpinp, DevId}}}, S = #?MODULE{root = Root}) ->
    [Txt] = ui:select(Root, [{id, {otpinp, DevId}}]),
    V = ui_textinput:get_text(Txt),
    mfa({submit_otp, DevId, V}, S);
mfa({ui, {clicked, {otpbtn, DevId}}}, S = #?MODULE{root = Root}) ->
    [Txt] = ui:select(Root, [{id, {otpinp, DevId}}]),
    V = ui_textinput:get_text(Txt),
    mfa({submit_otp, DevId, V}, S);

mfa({ui, {clicked, {pushbtn, DevId}}}, S = #?MODULE{duo = Duo, root = Root, peer = Peer, tsudcore = TsudCore, sess = #{user := U}, frontend = F}) ->
    [Name|_] = binary:split(unicode:characters_to_binary(
        TsudCore#tsud_core.client_name, {utf16, little}, utf8), [<<0>>]),
    [Maj,Min] = TsudCore#tsud_core.version,
    Version = iolist_to_binary(
        io_lib:format("version ~B.~B build ~w",
            [Maj, Min, TsudCore#tsud_core.client_build])),
    Caps = rdp_server:get_caps(F),
    GeneralCap = lists:keyfind(ts_cap_general, 1, Caps),
    [OsMaj, OsMin] = GeneralCap#ts_cap_general.os,
    OS = iolist_to_binary(
        io_lib:format("~w/~w", [OsMaj, OsMin])),
    PushInfo = uri_string:compose_query([
        {<<"client_name">>, Name},
        {<<"client_version">>, Version},
        {<<"client_os">>, OS}]),
    Args = #{
        <<"username">> => U,
        <<"ipaddr">> => Peer,
        <<"factor">> => <<"push">>,
        <<"device">> => DevId,
        <<"async">> => <<"true">>,
        <<"pushinfo">> => PushInfo
    },
    lager:debug("doing duo push: ~p", [Args]),
    [Chk] = ui:select(Root, [{id, rmbrchk}]),
    S1 = S#?MODULE{duoremember = ui_checkbox:get_checked(Chk)},
    case duo:auth(Duo, Args) of
        {ok, #{<<"result">> := <<"deny">>}} ->
            mfa(mfa_deny, S);
        {ok, #{<<"result">> := <<"allow">>}} ->
            mfa(allow, S1);
        {error, _} ->
            mfa(mfa_deny, S);
        {ok, #{<<"txid">> := TxId}} ->
            mfa_waiting(setup_ui, S1#?MODULE{duotx = TxId})
    end;

mfa({ui, {clicked, {smsbtn, DevId}}}, S = #?MODULE{duo = Duo, peer = Peer, sess = #{user := U}}) ->
    Args = #{
        <<"username">> => U,
        <<"ipaddr">> => Peer,
        <<"factor">> => <<"sms">>,
        <<"device">> => DevId
    },
    _ = duo:auth(Duo, Args),
    lager:debug("sending duo sms"),
    {next_state, mfa, S};

mfa({ui, {clicked, {callbtn, DevId}}}, S = #?MODULE{duo = Duo, root = Root, peer = Peer, sess = #{user := U}}) ->
    Args = #{
        <<"username">> => U,
        <<"ipaddr">> => Peer,
        <<"factor">> => <<"phone">>,
        <<"device">> => DevId,
        <<"async">> => <<"true">>
    },
    lager:debug("doing duo phone call"),
    [Chk] = ui:select(Root, [{id, rmbrchk}]),
    S1 = S#?MODULE{duoremember = ui_checkbox:get_checked(Chk)},
    case duo:auth(Duo, Args) of
        {ok, #{<<"result">> := <<"deny">>}} ->
            mfa(mfa_deny, S);
        {ok, #{<<"result">> := <<"allow">>}} ->
            mfa(allow, S1);
        {error, _} ->
            mfa(mfa_deny, S);
        {ok, #{<<"txid">> := TxId}} ->
            mfa_waiting(setup_ui, S1#?MODULE{duotx = TxId})
    end;

mfa({submit_otp, _DevId, Code}, S = #?MODULE{duo = Duo, root = Root, peer = Peer, sess = #{user := U}}) ->
    Args = #{
        <<"username">> => U,
        <<"ipaddr">> => Peer,
        <<"factor">> => <<"passcode">>,
        <<"passcode">> => Code
    },
    [Chk] = ui:select(Root, [{id, rmbrchk}]),
    S1 = S#?MODULE{duoremember = ui_checkbox:get_checked(Chk)},
    case duo:auth(Duo, Args) of
        {ok, R = #{<<"result">> := <<"deny">>}} ->
            lager:debug("user gave an invalid OTP code: ~p", [R]),
            mfa(mfa_deny, S);
        Err = {error, _} ->
            lager:debug("error reaching duo: ~p", [Err]),
            mfa(mfa_deny, S);
        {ok, #{<<"result">> := <<"allow">>}} ->
            lager:debug("used an OTP code, proceeding"),
            mfa(allow, S1)
    end;

mfa(allow, S = #?MODULE{uinfo = UInfo, listener = L, duoid = DuoId}) ->
    do_ping_annotate(S),
    Mode = rdpproxy:config([frontend, L, mode], pool),
    case S of
        #?MODULE{duoremember = true} ->
            #{user := U} = UInfo,
            ok = remember_ra:remember({DuoId, U});
        _ -> ok
    end,
    case Mode of
        nms_choice ->
            #?MODULE{frontend = F} = S,
            Shell = rdp_server:get_shell(F),
            lager:debug("shell = ~p", [Shell]),
            case frontend:parse_shell(Shell) of
                {none, _, _} ->
                    choose(setup_ui, S#?MODULE{pool = nms});
                {Hostname, Opts, _} ->
                    AdminACL = rdpproxy:config([ui, admin_acl],
                        [{deny, everybody}]),
                    Now = erlang:system_time(second),
                    S1 = S#?MODULE{pool = nms},
                    S2 = case lists:member(no_forward_creds, Opts) of
                        true ->
                            #?MODULE{sess = Sess0} = S,
                            Sess1 = Sess0#{password => <<>>, tgts => #{}},
                            S1#?MODULE{sess = Sess1};
                        false ->
                            S1
                    end,
                    case session_ra:process_rules(UInfo, Now, AdminACL) of
                        allow ->
                            lager:debug("shell host spec = ~p (opts = ~p)", [Hostname, Opts]),
                            choose({manual_host, Hostname}, S2);
                        deny ->
                            lager:debug("attempted to use shell host spec, but not an admin"),
                            choose(setup_ui, S2)
                    end
            end;
        {pool, Pool} ->
            {ok, PoolInfo} = session_ra:get_pool(Pool),
            case PoolInfo of
                #{choice := false} ->
                    waiting(setup_ui, S#?MODULE{pool = Pool});
                #{choice := true} ->
                    choose(setup_ui, S#?MODULE{pool = Pool})
            end;
        pool ->
            {ok, Pools0} = session_ra:get_pools_for(UInfo),
            NMSAcl = rdpproxy:config([ui, pool_nms_acl], [{deny, everybody}]),
            Now = erlang:system_time(second),
            Pools1 = case session_ra:process_rules(UInfo, Now, NMSAcl) of
                allow ->
                    [#{id => '_nms_pool', title => <<"NMS">>,
                       help_text => <<"Choose from personally assigned\nhosts in NMS.">>}
                     | Pools0];
                deny ->
                    Pools0
            end,
            case Pools1 of
                [#{id := Pool, choice := false}] ->
                    waiting(setup_ui, S#?MODULE{pool = Pool});
                [#{id := Pool, choice := true}] ->
                    choose(setup_ui, S#?MODULE{pool = Pool});
                _ ->
                    choose_pool(setup_ui, S)
            end
    end;

mfa(mfa_deny, S = #?MODULE{}) ->
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"Authentication failed">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, bgcolour()} }
    ],
    handle_root_events(mfa, S, Events).

mfa_waiting(setup_ui, S = #?MODULE{w = W, h = H, format = Fmt}) ->
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    {TopMod, LH} = case (H > W) of
        true -> {ui_vlayout, 200};
        false -> {ui_hlayout, H}
    end,
    {Msg, MsgLines} = get_msg(instruction_mfa_waiting, S),
    Events = [
        { [{id, root}],     {set_bgcolor, BgColour} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = TopMod}} },
        { [{id, hlayout}],  init },
        { [{id, hlayout}],  {set_halign, center} },
        { [{id, hlayout}],  {set_margin, 100} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = logo,
                                     mod = ui_image}} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = loginlyt,
                                     mod = ui_vlayout,
                                     size = {460.0, LH}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = banner,
                                     mod = ui_label,
                                     size = {400.0, 38.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = explain,
                                     mod = ui_label,
                                     size = {400.0, 18.0*MsgLines}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = closebtn,
                                     mod = ui_button,
                                     size = {120.0, 40.0}}} },

        { [{id, logo}],         {init, logopath()} },
        { [{id, banner}],       {init, left, rdpproxy:config([ui, title_mfa_waiting])} },
        { [{id, banner}],       {set_bgcolor, BgColour} },
        { [{id, explain}],      {init, left, Msg} },
        { [{id, explain}],      {set_bgcolor, BgColour} },
        { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(S, Orders),
    Fsm = self(),
    #?MODULE{duotx = TxId, duo = Duo} = S,
    Pid = spawn_link(fun () ->
        mfa_waiter(Fsm, Duo, TxId)
    end),
    lager:debug("spawned mfa_waiter ~p", [Pid]),
    {next_state, mfa_waiting, S#?MODULE{root = Root2}};

mfa_waiting({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            lager:debug("user hit escape"),
            rdp_server:close(F),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_inpevt_key{code = caps} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_inpevt_sync{} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_inpevt_unicode{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_suppress_output{allow_updates = false} ->
            {next_state, mfa_waiting, S};
        #ts_suppress_output{allow_updates = true} ->
            Event = { [{id, root}], redraw },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_refresh_rect{} ->
            Event = { [{id, root}], redraw },
            handle_root_events(mfa_waiting, S, [Event]);
        _ ->
            {next_state, mfa_waiting, S}
    end;

mfa_waiting({auth_finished, Result}, S = #?MODULE{}) ->
    case Result of
        #{<<"result">> := <<"allow">>} ->
            lager:debug("mfa finished, proceeding"),
            mfa(allow, S);
        R = #{<<"result">> := <<"deny">>} ->
            lager:debug("mfa denied async: ~p", [R]),
            {next_state, mfa, S1} = mfa(setup_ui, S),
            mfa(mfa_deny, S1);
        Other ->
            lager:debug("weird result from mfa wait: ~p", [Other]),
            mfa(setup_ui, S)
    end;

mfa_waiting({ui, {clicked, closebtn}}, S = #?MODULE{frontend = F}) ->
    lager:debug("user clicked closebtn"),
    rdp_server:close(F),
    {stop, normal, S}.

mfa_waiter(Fsm, Duo, TxId) ->
    case duo:auth_status(Duo, TxId) of
        {ok, #{<<"result">> := <<"waiting">>}} ->
            timer:sleep(1000),
            mfa_waiter(Fsm, Duo, TxId);
        {ok, Resp} ->
            gen_fsm:send_event(Fsm, {auth_finished, Resp}),
            exit(normal);
        Else ->
            lager:debug("mfa_waiter: ~p", [Else]),
            timer:sleep(1000),
            mfa_waiter(Fsm, Duo, TxId)
    end.

choose(setup_ui, S = #?MODULE{w = W, h = H, format = Fmt}) ->
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    {TopMod, LH} = case (H > W) of
        true -> {ui_vlayout, 2 * (H / 3)};
        false -> {ui_hlayout, H}
    end,
    BaseEvents0 = [
        { [{id, root}],     {set_bgcolor, BgColour} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = TopMod}} },
        { [{id, hlayout}],  init },
        { [{id, hlayout}],  {set_halign, center} },
        { [{id, hlayout}],  {set_margin, 100} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = logo,
                                     mod = ui_image}} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = loginlyt,
                                     mod = ui_vlayout,
                                     size = {440.0, LH}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = subbanner,
                                     mod = ui_label,
                                     size = {400.0, 36.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = instru,
                                     mod = ui_label,
                                     size = {400.0, 15.0}}} },

        { [{id, logo}],         {init, logopath()} },
        { [{id, subbanner}],    {init, left, rdpproxy:config([ui, title_choose])} },
        { [{id, subbanner}],    {set_bgcolor, BgColour} },
        { [{id, instru}],       {init, left, rdpproxy:config([ui, instruction_choose])} },
        { [{id, instru}],       {set_bgcolor, BgColour} }
    ],
    #?MODULE{uinfo = UInfo} = S,
    AdminACL = rdpproxy:config([ui, admin_acl], [{deny, everybody}]),
    Now = erlang:system_time(second),
    BaseEvents1 = case session_ra:process_rules(UInfo, Now, AdminACL) of
        allow -> BaseEvents0 ++ [
            { [{id, loginlyt}], {add_child,
                                #widget{id = itiglyt,
                                        mod = ui_vlayout,
                                        size = {400.0, 50.0}}} },
            { [{id, itiglyt}],  init },
            { [{id, itiglyt}],  {add_child,
                                #widget{id = itiglyt2,
                                        mod = ui_hlayout,
                                        size = {400.0, 30.0}}} },
            { [{id, itiglyt2}], init },
            { [{id, itiglyt2}], {add_child,
                                #widget{id = hostinp,
                                        mod = ui_textinput,
                                        size = {300.0, 28.0}}} },
            { [{id, itiglyt2}], {add_child,
                                #widget{id = itigbtn,
                                        mod = ui_button,
                                        size = {60.0, 28.0}}} },
            { [{id, itiglyt}],  {add_child,
                                #widget{id = credschk,
                                        mod = ui_checkbox,
                                        size = {200.0, 14.0}}} },

            { [{id, hostinp}],  {init, <<"hostname or ip">>} },
            { [{id, itigbtn}],  {init, <<"connect", 0>>} },
            { [{id, credschk}], {init, left, <<"forward credentials">>} },
            { [{id, credschk}], {set_bgcolor, BgColour} },

            { [{id, credschk}], {set_checked, true} },
            { [{id, hostinp}],  focus }
        ];
        deny -> BaseEvents0
    end,
    {Root2, Orders, []} = ui:handle_events(Root, BaseEvents1),
    send_orders(S, Orders),

    #?MODULE{sess = #{user := U}} = S,

    Devs0 = case S of
        #?MODULE{devs = OldDevs} when is_list(OldDevs) ->
            OldDevs;

        #?MODULE{nms = undefined, pool = Pool} ->
            {ok, Prefs} = session_ra:get_prefs(Pool, U),
            Devs = lists:map(fun (Ip) ->
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
            end, Devs),
            lists:map(fun (Dev) ->
                #{ip := Ip, handles := HDs, report_state := {St, _When},
                  role := Role, desc := Desc0} = Dev,
                OtherUserHDs = lists:filter(fun
                    (#{user := U2}) when (U2 =:= U) -> false;
                    (_) -> true
                end, HDs),
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
                    is_binary(Role) -> Role;
                    is_atom(Role) -> atom_to_binary(Role, latin1)
                end,
                Desc1 = case Desc0 of
                    none -> <<"IP address: ", Ip/binary>>;
                    _ -> Desc0
                end,
                Desc2 = <<Desc1/binary, "\nRole: ", RoleBin/binary>>,
                Dev#{desc => Desc2, busy => Busy}
            end, Devs);

        #?MODULE{nms = Nms} ->
            case nms:get_user_hosts(Nms, U) of
                {ok, D} ->
                    lists:map(fun (Dev) ->
                        #{<<"hostname">> := Hostname, <<"ip">> := Ip} = Dev,
                        DescText = case Dev of
                            #{<<"building">> := Building, <<"room">> := null} ->
                                <<Building/binary, ", unknown room\n",
                                  "IP address: ", Ip/binary>>;
                            #{<<"building">> := Building, <<"room">> := Room} ->
                                <<Building/binary, ", Room ", Room/binary, "\n",
                                  "IP address: ", Ip/binary>>;
                            #{<<"desc">> := Desc} -> Desc
                        end,
                        #{hostname => Hostname, ip => Ip, desc => DescText,
                          busy => false}
                    end, D);
                Err ->
                    lager:debug("failed to get user hosts from nms: ~p", [Err]),
                    []
            end
    end,
    {Off, Max, Devs1} = case S of
        #?MODULE{devoffset = undefined} ->
            {1, length(Devs0), lists:sublist(Devs0, ?devpgsize)};
        #?MODULE{devoffset = N} ->
            {N, length(Devs0), lists:sublist(Devs0, N, ?devpgsize)}
    end,
    lager:debug("giving ~p choice menu: ~p", [U, [Ip || #{ip := Ip} <- Devs1]]),

    Events1 = lists:foldl(fun (Dev, Acc) ->
        #{hostname := Hostname, ip := Ip, desc := DescText} = Dev,
        [Hostname1 | _] = binary:split(Hostname, [<<".">>]),
        Acc ++ [
                { [{id, loginlyt}],     {add_child,
                                         #widget{id = {devlyt, Ip},
                                                 mod = ui_hlayout,
                                                 size = {420.0, 80.0}}} },
                { [{id, {devlyt, Ip}}],  init },

                { [{id, {devlyt, Ip}}], {add_child,
                                         #widget{id = {devlbllyt, Ip},
                                                 mod = ui_vlayout,
                                                 size = {250.0, 80.0}}} },
                { [{id, {devlbllyt, Ip}}], init },

                { [{id, {devlbllyt, Ip}}],  {add_child,
                                          #widget{id = {devlbl, Ip},
                                                  mod = ui_label,
                                                  size = {220.0, 19.0}}} },
                { [{id, {devlbl, Ip}}],  {init, left, Hostname1} },
                { [{id, {devlbl, Ip}}],  {set_bgcolor, BgColour} },
                { [{id, {devlbllyt, Ip}}],  {add_child,
                                          #widget{id = {devtlbl, Ip},
                                                  mod = ui_label,
                                                  size = {220.0, 30.0}}} },
                { [{id, {devtlbl, Ip}}],  {init, left, DescText} },
                { [{id, {devtlbl, Ip}}],  {set_bgcolor, BgColour} }
        ] ++ (case Dev of
            #{busy := false} -> [
                { [{id, {devlyt, Ip}}], {add_child,
                                             #widget{id = {choosebtn, Ip, Hostname},
                                                     mod = ui_button,
                                                     size = {120.0, 28.0}}} },
                { [{id, {choosebtn, Ip, Hostname}}],  {init, <<"Connect", 0>>} }
                ];
            _ -> [
                { [{id, {devlyt, Ip}}], {add_child,
                                             #widget{id = {busylbl, Ip},
                                                     mod = ui_label,
                                                     size = {120.0, 18.0}}} },
                { [{id, {busylbl, Ip}}],  {init, center, <<"(Currently busy)">>} },
                { [{id, {busylbl, Ip}}],  {set_bgcolor, BgColour} }
            ]
        end)
    end, [], Devs1),
    Events2 = case Devs1 of
        [] ->
            {Msg, MsgLines} = get_msg(no_machines, S),
            Events1 ++ [
                { [{id, instru}],       {set_text, <<"\n">>} },
                { [{id, loginlyt}],     {add_child,
                                         #widget{id = nohostslbl,
                                                 mod = ui_label,
                                                 size = {400.0, 15.0 * MsgLines}}} },
                { [{id, nohostslbl}],   {init, left, Msg} },
                { [{id, nohostslbl}],   {set_bgcolor, BgColour} },

                { [{id, loginlyt}],     {add_child,
                                         #widget{id = closebtn,
                                                 mod = ui_button,
                                                 size = {120.0, 40.0}}} },
                { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
            ];
        _ -> Events1
    end,
    PageLblMsg = iolist_to_binary(io_lib:format("~B / ~B", [
        1 + (Off div ?devpgsize), (Max + ?devpgsize - 1) div ?devpgsize])),
    Events3 = Events2 ++ [
        { [{id, loginlyt}],     {add_child,
                                 #widget{id = pglyt,
                                         mod = ui_hlayout,
                                         size = {400.0, 40.0}}} },
        { [{id, pglyt}],        init },
        { [{id, pglyt}],        {add_child,
                                 #widget{id = refreshbtn,
                                         mod = ui_button,
                                         size = {120.0, 36.0}}} },
        { [{id, refreshbtn}],   {init, <<"Refresh list", 0>>} },
        { [{id, pglyt}],        {add_child,
                                 #widget{id = pagelbl,
                                         mod = ui_label,
                                         size = {40.0, 15.0}}} },
        { [{id, pagelbl}],      {init, center, PageLblMsg} },
        { [{id, pagelbl}],      {set_bgcolor, BgColour} },
        { [{id, pglyt}],        {add_child,
                                 #widget{id = prevpagebtn,
                                         mod = ui_button,
                                         size = {32.0, 36.0}}} },
        { [{id, prevpagebtn}],  {init, <<"<", 0>>} },
        { [{id, pglyt}],        {add_child,
                                 #widget{id = nextpagebtn,
                                         mod = ui_button,
                                         size = {32.0, 36.0}}} },
        { [{id, nextpagebtn}],  {init, <<">", 0>>} }
    ],
    {Root3, Orders2, []} = ui:handle_events(Root2, Events3),
    send_orders(S, Orders2),

    {next_state, choose, S#?MODULE{root = Root3, devs = Devs0}};

choose({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(choose, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            lager:debug("user hit escape"),
            rdp_server:close(F),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(choose, S, [Event]);
        #ts_inpevt_key{code = caps} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(choose, S, [Event]);
        #ts_inpevt_sync{} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(choose, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(choose, S, [Event]);
        #ts_inpevt_unicode{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(choose, S, [Event]);
        #ts_suppress_output{allow_updates = false} ->
            {next_state, choose, S};
        #ts_suppress_output{allow_updates = true} ->
            Event = { [{id, root}], redraw },
            handle_root_events(choose, S, [Event]);
        #ts_refresh_rect{} ->
            Event = { [{id, root}], redraw },
            handle_root_events(choose, S, [Event]);
        _ ->
            {next_state, choose, S}
    end;

choose({ui, {paste, TextInpId}}, S = #?MODULE{}) ->
    handle_paste(TextInpId, choose, S);

choose({ui, {clicked, closebtn}}, S = #?MODULE{frontend = F}) ->
    do_ping_annotate(S),
    lager:debug("user clicked closebtn"),
    rdp_server:close(F),
    {stop, normal, S};

choose({ui, {clicked, refreshbtn}}, S = #?MODULE{}) ->
    do_ping_annotate(S),
    choose(setup_ui, S#?MODULE{devs = undefined, devoffset = undefined});

choose({ui, {clicked, nextpagebtn}}, S = #?MODULE{devoffset = Off0, devs = Ds}) ->
    Off1 = case {Off0, length(Ds)} of
        {undefined, N} when N >= ?devpgsize -> ?devpgsize + 1;
        {_, N} when N >= (Off0 + ?devpgsize) -> Off0 + ?devpgsize;
        _ -> Off0
    end,
    do_ping_annotate(S),
    choose(setup_ui, S#?MODULE{devoffset = Off1});

choose({ui, {clicked, prevpagebtn}}, S = #?MODULE{devoffset = Off0, devs = Ds}) ->
    Off1 = case Off0 of
        undefined -> undefined;
        N when N > ?devpgsize -> Off0 - ?devpgsize;
        N when N =< ?devpgsize -> 1;
        _ -> Off0
    end,
    do_ping_annotate(S),
    choose(setup_ui, S#?MODULE{devoffset = Off1});

choose({ui, {submitted, hostinp}}, S = #?MODULE{}) ->
    choose({ui, {clicked, itigbtn}}, S);

choose({manual_host, HostText0}, S = #?MODULE{root = Root}) ->
    HostText1 = unicode:characters_to_list(HostText0, utf8),
    HostText2 = string:strip(HostText1, both),
    HostText = unicode:characters_to_binary(HostText2, utf8),
    {Ip, Hostname} = case inet:parse_address(HostText2) of
        {ok, IpInet} ->
            case session_ra:get_host(HostText) of
                {ok, #{hostname := HN}} -> {HostText, HN};
                _ ->
                    case http_api:rev_lookup(IpInet) of
                        {ok, RevLookupHN} ->
                            {HostText, iolist_to_binary([RevLookupHN])};
                        _ ->
                            {HostText, HostText}
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
                {[#{ip := Ip0, hostname := HN0} | _], _} -> {Ip0, HN0};
                {[], [#{ip := Ip0, hostname := HN0}]} -> {Ip0, HN0};
                _ ->
                    case inet_res:gethostbyname(HostText2) of
                        {ok, #hostent{h_name = RealName, h_addr_list = [Addr]}} ->
                            AddrBin = iolist_to_binary([inet:ntoa(Addr)]),
                            RealNameBin = iolist_to_binary([RealName]),
                            {AddrBin, RealNameBin};
                        Err ->
                            lager:debug("failed to lookup ~p: ~p", [
                                HostText, Err]),
                            {unknown, HostText}
                    end
            end
    end,
    case Ip of
        unknown ->
            %% TODO: display error message
            {next_state, choose, S};
        _ ->
            choose({ui, {clicked, {choosebtn, Ip, Hostname}}}, S)
    end;

choose({ui, {clicked, itigbtn}}, S = #?MODULE{root = Root}) ->
    [HostInp] = ui:select(Root, [{id, hostinp}]),
    HostText = ui_textinput:get_text(HostInp),
    choose({manual_host, HostText}, S);

choose({ui, {clicked, {choosebtn, Ip, Hostname}}}, S = #?MODULE{sess = Sess0, root = Root}) ->
    FwdCreds = case ui:select(Root, [{id, credschk}]) of
        [FwdCredsChkBox] -> ui_checkbox:get_checked(FwdCredsChkBox);
        [] -> true
    end,
    Sess1 = case FwdCreds of
        true -> Sess0#{ip => Ip, port => 3389};
        false -> Sess0#{ip => Ip, port => 3389, password => <<>>, tgts => #{}}
    end,
    _ = session_ra:create_host(#{
        pool => default,
        ip => Ip,
        port => 3389,
        hostname => Hostname}),
    _ = session_ra:update_host(#{ip => Ip, hostname => Hostname}),
    lager:debug("user chose host ~p/~p", [Hostname, Ip]),
    case S of
        #?MODULE{nms = undefined} -> ok;
        #?MODULE{nms = Nms} ->
            Ret = nms:wol(Nms, Hostname),
            lager:debug("wol for ~p returned ~p", [Hostname, Ret])
    end,
    waiting(setup_ui, S#?MODULE{sess = Sess1}).

choose_pool(setup_ui, S = #?MODULE{w = W, h = H, format = Fmt}) ->
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    {TopMod, LH} = case (H > W) of
        true -> {ui_vlayout, 2 * (H / 3)};
        false -> {ui_hlayout, H}
    end,
    {InstrText, InstrLines} = get_msg(instruction_choose_pool, S),
    Events0 = [
        { [{id, root}],     {set_bgcolor, BgColour} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = TopMod}} },
        { [{id, hlayout}],  init },
        { [{id, hlayout}],  {set_halign, center} },
        { [{id, hlayout}],  {set_margin, 100} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = logo,
                                     mod = ui_image}} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = loginlyt,
                                     mod = ui_vlayout,
                                     size = {440.0, LH}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = subbanner,
                                     mod = ui_label,
                                     size = {400.0, 36.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = instru,
                                     mod = ui_label,
                                     size = {400.0, 15.0 * InstrLines}}} },

        { [{id, logo}],         {init, logopath()} },
        { [{id, subbanner}],    {init, left, rdpproxy:config([ui, title_choose_pool])} },
        { [{id, subbanner}],    {set_bgcolor, BgColour} },
        { [{id, instru}],       {init, left, InstrText} },
        { [{id, instru}],       {set_bgcolor, BgColour} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events0),
    send_orders(S, Orders),

    #?MODULE{uinfo = UInfo = #{user := U}} = S,
    Pools0 = case S of
        #?MODULE{pools = undefined} ->
            {ok, Ps} = session_ra:get_pools_for(UInfo),
            Ps;
        #?MODULE{pools = Ps} ->
            Ps
    end,
    NMSAcl = rdpproxy:config([ui, pool_nms_acl], [{deny, everybody}]),
    Now = erlang:system_time(second),
    Pools1 = case session_ra:process_rules(UInfo, Now, NMSAcl) of
        allow ->
            [#{id => '_nms_pool', title => <<"NMS">>,
               help_text => <<"Choose from personally assigned\nhosts in NMS.">>}
             | Pools0];
        deny ->
            Pools0
    end,
    {Off, Max, Pools2} = case S of
        #?MODULE{pooloffset = undefined} ->
            {1, length(Pools1), lists:sublist(Pools1, ?devpgsize)};
        #?MODULE{pooloffset = N} ->
            {N, length(Pools1), lists:sublist(Pools1, N, ?devpgsize)}
    end,
    lager:debug("giving ~p pool choice menu: ~p", [U, Pools1]),

    Events1 = lists:foldl(fun (PD, Acc) ->
        #{id := Id, title := Title, help_text := HelpText} = PD,
        HelpTextLines = length(binary:matches(HelpText, [<<"\n">>])) + 1,
        Acc ++ [
                { [{id, loginlyt}],     {add_child,
                                         #widget{id = {devlyt, Id},
                                                 mod = ui_hlayout,
                                                 size = {420.0, 80.0}}} },
                { [{id, {devlyt, Id}}],  init },

                { [{id, {devlyt, Id}}], {add_child,
                                         #widget{id = {devlbllyt, Id},
                                                 mod = ui_vlayout,
                                                 size = {250.0, 80.0}}} },
                { [{id, {devlbllyt, Id}}], init },

                { [{id, {devlbllyt, Id}}],  {add_child,
                                          #widget{id = {devlbl, Id},
                                                  mod = ui_label,
                                                  size = {220.0, 19.0}}} },
                { [{id, {devlbl, Id}}],  {init, left, Title} },
                { [{id, {devlbl, Id}}],  {set_bgcolor, BgColour} },
                { [{id, {devlbllyt, Id}}],  {add_child,
                                          #widget{id = {devtlbl, Id},
                                                  mod = ui_label,
                                                  size = {220.0, 15.0 * HelpTextLines}}} },
                { [{id, {devtlbl, Id}}],  {init, left, HelpText} },
                { [{id, {devtlbl, Id}}],  {set_bgcolor, BgColour} },

                { [{id, {devlyt, Id}}], {add_child,
                                             #widget{id = {choosebtn, Id},
                                                     mod = ui_button,
                                                     size = {120.0, 28.0}}} },
                { [{id, {choosebtn, Id}}],  {init, <<"Connect", 0>>} }
        ]
    end, [], Pools2),
    PageLblMsg = iolist_to_binary(io_lib:format("~B / ~B", [
        1 + (Off div ?devpgsize), (Max + ?devpgsize - 1) div ?devpgsize])),
    Events2 = Events1 ++ [
        { [{id, loginlyt}],     {add_child,
                                 #widget{id = pglyt,
                                         mod = ui_hlayout,
                                         size = {400.0, 40.0}}} },
        { [{id, pglyt}],        init },
        { [{id, pglyt}],        {add_child,
                                 #widget{id = pagelbl,
                                         mod = ui_label,
                                         size = {40.0, 15.0}}} },
        { [{id, pagelbl}],      {init, center, PageLblMsg} },
        { [{id, pagelbl}],      {set_bgcolor, BgColour} },
        { [{id, pglyt}],        {add_child,
                                 #widget{id = prevpagebtn,
                                         mod = ui_button,
                                         size = {32.0, 36.0}}} },
        { [{id, prevpagebtn}],  {init, <<"<", 0>>} },
        { [{id, pglyt}],        {add_child,
                                 #widget{id = nextpagebtn,
                                         mod = ui_button,
                                         size = {32.0, 36.0}}} },
        { [{id, nextpagebtn}],  {init, <<">", 0>>} }
    ],
    {Root3, Orders2, []} = ui:handle_events(Root2, Events2),
    send_orders(S, Orders2),

    {next_state, choose_pool, S#?MODULE{root = Root3, pools = Pools0}};

choose_pool({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(choose_pool, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            lager:debug("user hit escape"),
            rdp_server:close(F),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(choose_pool, S, [Event]);
        #ts_inpevt_key{code = caps} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(choose_pool, S, [Event]);
        #ts_inpevt_sync{} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(choose_pool, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(choose_pool, S, [Event]);
        #ts_inpevt_unicode{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(choose_pool, S, [Event]);
        #ts_suppress_output{allow_updates = false} ->
            {next_state, choose_pool, S};
        #ts_suppress_output{allow_updates = true} ->
            Event = { [{id, root}], redraw },
            handle_root_events(choose_pool, S, [Event]);
        #ts_refresh_rect{} ->
            Event = { [{id, root}], redraw },
            handle_root_events(choose_pool, S, [Event]);
        _ ->
            {next_state, choose_pool, S}
    end;

choose_pool({ui, {clicked, closebtn}}, S = #?MODULE{frontend = F}) ->
    lager:debug("user clicked closebtn"),
    do_ping_annotate(S),
    rdp_server:close(F),
    {stop, normal, S};

choose_pool({ui, {clicked, nextpagebtn}}, S = #?MODULE{pooloffset = Off0, pools = Ds}) ->
    Off1 = case {Off0, length(Ds)} of
        {undefined, N} when N >= ?devpgsize -> ?devpgsize + 1;
        {_, N} when N >= (Off0 + ?devpgsize) -> Off0 + ?devpgsize;
        _ -> Off0
    end,
    do_ping_annotate(S),
    choose_pool(setup_ui, S#?MODULE{pooloffset = Off1});

choose_pool({ui, {clicked, prevpagebtn}}, S = #?MODULE{pooloffset = Off0, pools = Ds}) ->
    Off1 = case Off0 of
        undefined -> undefined;
        N when N > ?devpgsize -> Off0 - ?devpgsize;
        N when N =< ?devpgsize -> 1;
        _ -> Off0
    end,
    do_ping_annotate(S),
    choose_pool(setup_ui, S#?MODULE{pooloffset = Off1});

choose_pool({ui, {clicked, {choosebtn, '_nms_pool'}}}, S = #?MODULE{}) ->
    do_ping_annotate(S),
    {ok, Nms} = nms:start_link(),
    choose(setup_ui, S#?MODULE{nms = Nms});

choose_pool({ui, {clicked, {choosebtn, Id}}}, S = #?MODULE{}) ->
    do_ping_annotate(S),
    case session_ra:get_pool(Id) of
        {ok, #{choice := false}} ->
            waiting(setup_ui, S#?MODULE{pool = Id});
        {ok, #{choice := true}} ->
            choose(setup_ui, S#?MODULE{pool = Id});
        _ ->
            timer:sleep(1000),
            choose_pool({ui, {clicked, {choosebtn, Id}}}, S)
    end.

waiting(setup_ui, S = #?MODULE{w = W, h = H, format = Fmt, listener = L}) ->
    do_ping_annotate(S),
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    {TopMod, LH} = case (H > W) of
        true -> {ui_vlayout, 200};
        false -> {ui_hlayout, H}
    end,
    T0 = erlang:system_time(millisecond),
    Mode = rdpproxy:config([frontend, L, mode], pool),
    Text = case Mode of
        pool ->       <<"Looking for an available computer to\n"
                        "log you in...\n">>;
        {pool, _} ->  <<"Looking for an available computer to\n"
                        "log you in...\n">>;
        nms_choice -> <<"Checking to see if computer is available\n",
                        "and ready to log you in...\n">>
    end,
    Events = [
        { [{id, root}],     {set_bgcolor, BgColour} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = TopMod}} },
        { [{id, hlayout}],  init },
        { [{id, hlayout}],  {set_halign, center} },
        { [{id, hlayout}],  {set_margin, 100} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = logo,
                                     mod = ui_image}} },
        { [{id, hlayout}],  {add_child,
                             #widget{id = loginlyt,
                                     mod = ui_vlayout,
                                     size = {460.0, LH}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = banner,
                                     mod = ui_label,
                                     size = {400.0, 38.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = explain,
                                     mod = ui_label,
                                     size = {400.0, 18.0*3}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = closebtn,
                                     mod = ui_button,
                                     size = {120.0, 40.0}}} },

        { [{id, logo}],         {init, logopath()} },
        { [{id, banner}],       {init, left, <<"Please wait...">>} },
        { [{id, banner}],       {set_bgcolor, BgColour} },
        { [{id, explain}],      {init, left, Text} },
        { [{id, explain}],      {set_bgcolor, BgColour} },
        { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(S, Orders),
    #?MODULE{pool = Pool, sess = Sess} = S,
    {ok, AllocPid} = host_alloc_fsm:start(Pool, Sess),
    MRef = erlang:monitor(process, AllocPid),
    {next_state, waiting, S#?MODULE{root = Root2, allocpid = AllocPid,
        allocmref = MRef, waitstart = T0}};

waiting({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            T1 = erlang:system_time(millisecond),
            #?MODULE{waitstart = T0, sess = #{user := U}} = S,
            prometheus_summary:observe(rdpproxy_waiting_time_milliseconds,
                T1 - T0),
            prometheus_counter:inc(rdpproxy_wait_aborts_total),
            lager:debug("user hit escape"),
            rdp_server:close(F),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_key{code = caps} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_sync{} ->
            Event = { [{tag, focusable}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_unicode{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_suppress_output{allow_updates = false} ->
            {next_state, waiting, S};
        #ts_suppress_output{allow_updates = true} ->
            Event = { [{id, root}], redraw },
            handle_root_events(waiting, S, [Event]);
        #ts_refresh_rect{} ->
            Event = { [{id, root}], redraw },
            handle_root_events(waiting, S, [Event]);
        _ ->
            {next_state, waiting, S}
    end;

waiting({allocated_session, AllocPid, Sess}, S = #?MODULE{frontend = F = {FPid, _}, allocpid = AllocPid, listener = L}) ->
    #{handle := Cookie, ip := Ip, user := U, sessid := SessId} = Sess,
    T1 = erlang:system_time(millisecond),
    #?MODULE{waitstart = T0} = S,
    prometheus_summary:observe(rdpproxy_waiting_time_milliseconds, T1 - T0),
    erlang:demonitor(S#?MODULE.allocmref, [flush]),
    #?MODULE{nms = Nms} = S,
    case Nms of
        undefined -> ok;
        _ ->
            case nms:bump_count(Nms, U, Ip) of
                {ok, _} -> ok;
                Else -> lager:debug("nms:bump_count returned ~p", [Else])
            end
    end,
    conn_ra:annotate(FPid, #{session => Sess#{password => snip, tgts => snip}}),
    do_ping_annotate(S),
    rdp_server:send_redirect(F, Cookie, SessId,
        rdpproxy:config([frontend, L, hostname], <<"localhost">>)),
    {stop, normal, S};

waiting({alloc_persistent_error, AllocPid, bad_cert}, S = #?MODULE{allocpid = AllocPid}) ->
    do_ping_annotate(S),
    LightRed = {1.0, 0.8, 0.8},
    {Msg, MsgLines} = get_msg(err_cert, S),
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, closebtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0 * MsgLines}}
            } },
        { [{id, badlbl}],   {init, center, Msg} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, bgcolour()} }
    ],
    handle_root_events(waiting, S, Events);

waiting({alloc_persistent_error, AllocPid, no_ssl}, S = #?MODULE{allocpid = AllocPid}) ->
    do_ping_annotate(S),
    LightRed = {1.0, 0.8, 0.8},
    {Msg, MsgLines} = get_msg(err_ssl, S),
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, closebtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0 * MsgLines}}
            } },
        { [{id, badlbl}],   {init, center, Msg} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, bgcolour()} }
    ],
    handle_root_events(waiting, S, Events);

waiting({alloc_persistent_error, AllocPid, credssp_required}, S = #?MODULE{allocpid = AllocPid}) ->
    do_ping_annotate(S),
    LightRed = {1.0, 0.8, 0.8},
    {Msg, MsgLines} = get_msg(err_credssp_req, S),
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, closebtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0 * MsgLines}}
            } },
        { [{id, badlbl}],   {init, center, Msg} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, bgcolour()} }
    ],
    handle_root_events(waiting, S, Events);

waiting({alloc_persistent_error, AllocPid, down}, S = #?MODULE{allocpid = AllocPid}) ->
    do_ping_annotate(S),
    LightRed = {1.0, 0.8, 0.8},
    {Msg, MsgLines} = get_msg(err_unreach, S),
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, closebtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0 * MsgLines}}
            } },
        { [{id, badlbl}],   {init, center, Msg} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, bgcolour()} }
    ],
    #?MODULE{nms = Nms, sess = #{ip := Ip}} = S,
    Ret = nms:wol(Nms, Ip),
    lager:debug("wol for ~p returned ~p", [Ip, Ret]),
    handle_root_events(waiting, S, Events);

waiting({alloc_persistent_error, AllocPid, refused}, S = #?MODULE{allocpid = AllocPid}) ->
    do_ping_annotate(S),
    LightRed = {1.0, 0.8, 0.8},
    {Msg, MsgLines} = get_msg(err_refused, S),
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, closebtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0 * MsgLines}}
            } },
        { [{id, badlbl}],   {init, center, Msg} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, bgcolour()} }
    ],
    handle_root_events(waiting, S, Events);

waiting({'DOWN', MRef, process, _, _}, S = #?MODULE{allocmref = MRef, pool = P, sess = Sess}) ->
    {ok, AllocPid} = host_alloc_fsm:start(P, Sess),
    NewMRef = erlang:monitor(process, AllocPid),
    {next_state, waiting, S#?MODULE{allocpid = AllocPid, allocmref = NewMRef}};

waiting({ui, {clicked, closebtn}}, S = #?MODULE{frontend = F}) ->
    T1 = erlang:system_time(millisecond),
    do_ping_annotate(S),
    #?MODULE{waitstart = T0, sess = #{user := U}} = S,
    prometheus_summary:observe(rdpproxy_waiting_time_milliseconds, T1 - T0),
    prometheus_counter:inc(rdpproxy_wait_aborts_total),
    lager:debug("user clicked closebtn"),
    rdp_server:close(F),
    {stop, normal, S}.

handle_info({'DOWN', MRef, process, _, _}, _State, S = #?MODULE{mref = MRef}) ->
    {stop, normal, S};
handle_info({scard_result, _}, State, S = #?MODULE{}) ->
    {next_state, State, S};
handle_info(Msg, State, S = #?MODULE{}) ->
    ?MODULE:State(Msg, S).


%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.

-endif.

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
