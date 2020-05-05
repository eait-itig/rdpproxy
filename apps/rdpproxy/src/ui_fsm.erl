%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2019 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
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
-behaviour(gen_fsm).

-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/kbd.hrl").
-include_lib("rdp_proto/include/tsud.hrl").
-include_lib("cairerl/include/cairerl.hrl").
-include_lib("rdp_ui/include/ui.hrl").

-include_lib("kernel/include/inet.hrl").

-export([start_link/2]).
-export([startup/2, login/2, no_redir/2, waiting/2, mfa/2, mfa_waiting/2, choose/2, choose_pool/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).
-export([handle_event/3, handle_sync_event/4]).

-spec start_link(Frontend :: rdp_server:server(), Listener :: atom()) -> {ok, pid()} | {error, term()}.
start_link(Frontend, L) ->
    gen_fsm:start_link(?MODULE, [Frontend, L], []).

-record(?MODULE, {
    frontend :: rdp_server:server(),
    listener :: atom(),
    mref :: reference(),
    w = 0.0 :: float(), h = 0.0 :: float(),
    bpp = 16 :: integer(),
    format = rgb24 :: atom(),
    root :: undefined | #widget{},
    sess :: undefined | session_ra:handle_state(),
    peer :: undefined | binary(),
    tsudcore :: undefined | #tsud_core{},
    uinfo :: undefined | session_ra:user_info(),
    pool :: undefined | session_ra:pool(),
    allocpid :: undefined | pid(),
    allocmref :: undefined | reference(),
    nms :: undefined | pid(),
    duo :: undefined | pid(),
    duodevs :: undefined | [map()],
    duoid :: undefined | binary(),
    duotx :: undefined | binary(),
    duoremember = false :: boolean()}).

%% @private
init([Frontend, L]) ->
    {Pid, _} = Frontend,
    lager:debug("ui_fsm for frontend ~p", [Pid]),
    gen_fsm:send_event(Pid, {subscribe, self()}),
    MRef = monitor(process, Pid),
    {ok, startup, #?MODULE{mref = MRef, frontend = Frontend, listener = L}, 0}.

handle_event(_Evt, State, S) ->
    {next_state, State, S}.

handle_sync_event(_Evt, _From, State, S) ->
    {reply, {error, unknown_event}, State, S}.

send_orders(#?MODULE{frontend = F, format = Fmt}, Orders) ->
    Updates = ui:orders_to_updates(Orders, Fmt),
    lists:foreach(fun(U) ->
        rdp_server:send_update(F, U)
    end, Updates).

handle_root_events(State, S = #?MODULE{root = Root}, Events) ->
    {Root2, Orders, UiEvts} = ui:handle_events(Root, Events),
    lists:foreach(fun(UiEvt) ->
        gen_fsm:send_event(self(), {ui, UiEvt})
    end, UiEvts),
    send_orders(S, Orders),
    {next_state, State, S#?MODULE{root = Root2}}.

bgcolour() ->
    {R, G, B} = rdpproxy:config([ui, bg_colour], {16#49, 16#07, 16#5e}),
    {R / 256, G / 256, B / 256}.

logopath() ->
    lists:flatten([code:priv_dir(rdpproxy), $/,
        rdpproxy:config([ui, logo], "uq-logo.png")]).

get_msg(Name, #?MODULE{sess = #{user := U}}) ->
    Msg0 = rdpproxy:config([ui, Name]),
    Msg1 = binary:replace(Msg0, [<<"%USER%">>], U, [global]),
    Msg2 = binary:replace(Msg1, [<<"%HELPDESK%">>],
        rdpproxy:config([ui, helpdesk]), [global]),
    MsgLines = length(binary:matches(Msg2, [<<"\n">>])) + 1,
    {Msg2, MsgLines};
get_msg(Name, #?MODULE{}) ->
    Msg0 = rdpproxy:config([ui, Name]),
    Msg1 = binary:replace(Msg0, [<<"%HELPDESK%">>],
        rdpproxy:config(ui, helpdesk), [global]),
    MsgLines = length(binary:matches(Msg1, [<<"\n">>])) + 1,
    {Msg1, MsgLines}.

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

    ClientFp = crypto:hash(sha256, [
        term_to_binary(PeerIp),
        term_to_binary(GeneralCap#ts_cap_general.os),
        term_to_binary(TsudCore#tsud_core.version),
        term_to_binary(TsudCore#tsud_core.client_build),
        term_to_binary(TsudCore#tsud_core.client_name),
        term_to_binary(TsudCore#tsud_core.capabilities),
        term_to_binary(TsudCore#tsud_core.prodid),
        term_to_binary(ChanNames)
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
            {ok, Duo} = duo:start_link(),
            Mode = rdpproxy:config([frontend, L, mode], pool),
            case Mode of
                nms_choice ->
                    {ok, Nms} = nms:start_link(),
                    login(setup_ui, S2#?MODULE{duo = Duo, nms = Nms});
                _ ->
                    login(setup_ui, S2#?MODULE{duo = Duo})
            end
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

    {Root3, Orders2, []} = ui:handle_events(Root2, Events2),
    send_orders(S, Orders2),

    {next_state, login, S#?MODULE{root = Root3}};

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
        _ ->
            {next_state, login, S}
    end;

login({ui, {submitted, userinp}}, S = #?MODULE{}) ->
    Event = { [{id, passinp}], focus },
    handle_root_events(login, S, [Event]);

login({ui, {submitted, passinp}}, S = #?MODULE{}) ->
    login(check_creds, S);

login({ui, {clicked, loginbtn}}, S = #?MODULE{}) ->
    login(check_creds, S);

login(check_creds, S = #?MODULE{root = Root, duo = Duo, listener = L, frontend = {FPid,_}}) ->
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
            Creds = #{
                username => iolist_to_binary([Username]),
                password => iolist_to_binary([Password])
            },
            case krb_auth:authenticate(Creds) of
                {true, UInfo} ->
                    lager:debug("auth for ~p succeeded!", [Username]),
                    #?MODULE{duoid = DuoId, peer = Peer} = S,
                    Sess0 = #{user => Username, domain => Domain,
                        password => Password},
                    conn_ra:annotate(FPid, #{session => Sess0#{ip => undefined, password => snip}}),
                    S1 = S#?MODULE{sess = Sess0, uinfo = UInfo},
                    Args = #{
                        <<"username">> => Username,
                        <<"ipaddr">> => Peer,
                        <<"trusted_device_token">> => DuoId
                    },
                    EnrollIsAllow = rdpproxy:config([duo, enroll_is_allow], false),
                    case duo:preauth(Duo, Args) of
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
                        Else ->
                            lager:debug("duo preauth else for ~p: ~p", [Username, Else]),
                            login(invalid_login, S)
                    end;
                false ->
                    lager:debug("auth for ~p failed", [Username]),
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

login(mfa_enroll, S = #?MODULE{}) ->
    BgColour = bgcolour(),
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"MFA required but not enrolled">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, BgColour} }
    ],
    handle_root_events(login, S, Events).

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
        _ ->
            {next_state, mfa, S}
    end;

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
        {ok, #{<<"result">> := <<"deny">>}} ->
            lager:debug("user gave an invalid OTP code"),
            mfa(mfa_deny, S);
        {error, _} ->
            mfa(mfa_deny, S);
        {ok, #{<<"result">> := <<"allow">>}} ->
            lager:debug("used an OTP code, proceeding"),
            mfa(allow, S1)
    end;

mfa(allow, S = #?MODULE{uinfo = UInfo, listener = L, duoid = DuoId}) ->
    Mode = rdpproxy:config([frontend, L, mode], pool),
    case S of
        #?MODULE{duoremember = true} ->
            #{user := U} = UInfo,
            ok = remember_ra:remember({DuoId, U});
        _ -> ok
    end,
    case Mode of
        nms_choice ->
            choose(setup_ui, S#?MODULE{pool = nms});
        {pool, Pool} ->
            {ok, PoolInfo} = session_ra:get_pool(Pool),
            case PoolInfo of
                #{choice := false} ->
                    waiting(setup_ui, S#?MODULE{pool = Pool});
                #{choice := true} ->
                    choose(setup_ui, S#?MODULE{pool = Pool})
            end;
        pool ->
            {ok, Pools} = session_ra:get_pools_for(UInfo),
            case Pools of
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
        _ ->
            {next_state, mfa_waiting, S}
    end;

mfa_waiting({auth_finished, Result}, S = #?MODULE{}) ->
    case Result of
        #{<<"result">> := <<"allow">>} ->
            lager:debug("mfa finished, proceeding"),
            mfa(allow, S);
        _ ->
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
    BaseEvents1 = case session_ra:process_rules(UInfo, AdminACL) of
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
                    (#{user := _U}) -> false;
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
                    (#{user := _U}) -> false;
                    (_) -> true
                end, HDs),
                Busy = case {AnyAvail, OtherUserHDs, St} of
                    % Always allow selecting available machines with 0 handles
                    {_, [], available} -> false;
                    % Allow selecting machines with active handles if
                    % there are no available machines
                    {false, _, available} -> false;
                    % Also allow selecting "busy" machines without any active
                    % handles if nothing else is available
                    {false, [], busy} -> false;
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
    Devs1 = lists:sublist(Devs0, 6),
    lager:debug("giving ~p choice menu: ~p", [U, [Ip || #{ip := Ip} <- Devs1]]),

    Events1 = lists:foldl(fun (Dev, Acc) ->
        #{hostname := Hostname, ip := Ip, desc := DescText} = Dev,
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
                { [{id, {devlbl, Ip}}],  {init, left, Hostname} },
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
    Events3 = Events2 ++ [
        { [{id, loginlyt}],     {add_child,
                                 #widget{id = refreshbtn,
                                         mod = ui_button,
                                         size = {120.0, 36.0}}} },
        { [{id, refreshbtn}],     {init, <<"Refresh list", 0>>} }
    ],
    {Root3, Orders2, []} = ui:handle_events(Root2, Events3),
    send_orders(S, Orders2),

    {next_state, choose, S#?MODULE{root = Root3}};

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
        _ ->
            {next_state, choose, S}
    end;

choose({ui, {clicked, closebtn}}, S = #?MODULE{frontend = F}) ->
    lager:debug("user clicked closebtn"),
    rdp_server:close(F),
    {stop, normal, S};

choose({ui, {clicked, refreshbtn}}, S = #?MODULE{}) ->
    choose(setup_ui, S);

choose({ui, {submitted, hostinp}}, S = #?MODULE{}) ->
    choose({ui, {clicked, itigbtn}}, S);

choose({ui, {clicked, itigbtn}}, S = #?MODULE{root = Root}) ->
    [HostInp] = ui:select(Root, [{id, hostinp}]),
    HostText = ui_textinput:get_text(HostInp),
    {Ip, Hostname} = case inet:parse_address(binary_to_list(HostText)) of
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
                    case inet_res:gethostbyname(binary_to_list(HostText)) of
                        {ok, #hostent{h_addr_list = [Addr]}} ->
                            AddrBin = iolist_to_binary([inet:ntoa(Addr)]),
                            {AddrBin, HostText};
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

choose({ui, {clicked, {choosebtn, Ip, Hostname}}}, S = #?MODULE{sess = Sess0, root = Root}) ->
    [FwdCredsChkBox] = ui:select(Root, [{id, credschk}]),
    FwdCreds = ui_checkbox:get_checked(FwdCredsChkBox),
    Sess1 = case FwdCreds of
        true -> Sess0#{ip => Ip, port => 3389};
        false -> Sess0#{ip => Ip, port => 3389, password => <<"">>}
    end,
    _ = session_ra:create_host(#{
        pool => default,
        ip => Ip,
        port => 3389,
        hostname => Hostname}),
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
    {ok, Pools0} = session_ra:get_pools_for(UInfo),
    Pools1 = lists:sublist(Pools0, 6),
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
    end, [], Pools1),
    {Root3, Orders2, []} = ui:handle_events(Root2, Events1),
    send_orders(S, Orders2),

    {next_state, choose_pool, S#?MODULE{root = Root3}};

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
        _ ->
            {next_state, choose_pool, S}
    end;

choose_pool({ui, {clicked, closebtn}}, S = #?MODULE{frontend = F}) ->
    lager:debug("user clicked closebtn"),
    rdp_server:close(F),
    {stop, normal, S};

choose_pool({ui, {clicked, {choosebtn, Id}}}, S = #?MODULE{}) ->
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
    BgColour = bgcolour(),
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    {TopMod, LH} = case (H > W) of
        true -> {ui_vlayout, 200};
        false -> {ui_hlayout, H}
    end,
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
    {next_state, waiting, S#?MODULE{root = Root2, allocpid = AllocPid, allocmref = MRef}};

waiting({input, F = {Pid,_}, Evt}, S = #?MODULE{frontend = {Pid,_}, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
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
        _ ->
            {next_state, waiting, S}
    end;

waiting({allocated_session, AllocPid, Sess}, S = #?MODULE{frontend = F = {FPid, _}, allocpid = AllocPid, listener = L}) ->
    #{handle := Cookie, ip := Ip, user := U, sessid := SessId} = Sess,
    erlang:demonitor(S#?MODULE.allocmref),
    #?MODULE{nms = Nms} = S,
    case Nms of
        undefined -> ok;
        _ ->
            case nms:bump_count(Nms, U, Ip) of
                {ok, _} -> ok;
                Else -> lager:debug("nms:bump_count returned ~p", [Else])
            end
    end,
    conn_ra:annotate(FPid, #{session => Sess#{password => snip}}),
    rdp_server:send_redirect(F, Cookie, SessId,
        rdpproxy:config([frontend, L, hostname], <<"localhost">>)),
    {stop, normal, S};

waiting({alloc_persistent_error, AllocPid, no_ssl}, S = #?MODULE{allocpid = AllocPid}) ->
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

waiting({alloc_persistent_error, AllocPid, down}, S = #?MODULE{allocpid = AllocPid}) ->
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
    lager:debug("user clicked closebtn"),
    rdp_server:close(F),
    {stop, normal, S}.

handle_info({'DOWN', MRef, process, _, _}, _State, S = #?MODULE{mref = MRef}) ->
    {stop, normal, S};
handle_info(Msg, State, S = #?MODULE{}) ->
    ?MODULE:State(Msg, S).

%% @private
terminate(_Reason, _State, #?MODULE{duo = undefined, nms = undefined}) ->
    ok;
terminate(_Reason, _State, #?MODULE{duo = Duo, nms = Nms}) ->
    duo:stop(Duo),
    case Nms of
        undefined -> ok;
        _ -> nms:stop(Nms)
    end,
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
