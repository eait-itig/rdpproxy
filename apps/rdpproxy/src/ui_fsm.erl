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
-include_lib("cairerl/include/cairerl.hrl").
-include_lib("rdp_ui/include/ui.hrl").

-include("session.hrl").

-export([start_link/1]).
-export([startup/2, login/2, no_redir/2, waiting/2, mfa/2, mfa_waiting/2, choose/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid()) -> {ok, pid()}.
start_link(Frontend) ->
    gen_fsm:start_link(?MODULE, [Frontend], []).

-record(state, {
    frontend,
    mref,
    w, h, bpp, format,
    root, sess,
    allocpid, allocmref,
    duo, nms,
    duodevs, machines, duotx}).

%% @private
init([Frontend]) ->
    {Pid, _} = Frontend,
    gen_fsm:send_event(Pid, {subscribe, self()}),
    MRef = monitor(process, Pid),
    {ok, startup, #state{mref = MRef, frontend = Frontend}, 0}.

send_orders(#state{frontend = F, format = Fmt}, Orders) ->
    Updates = ui:orders_to_updates(Orders, Fmt),
    lists:foreach(fun(U) ->
        rdp_server:send_update(F, U)
    end, Updates).

handle_root_events(State, S = #state{root = Root}, Events) ->
    {Root2, Orders, UiEvts} = ui:handle_events(Root, Events),
    lists:foreach(fun(UiEvt) ->
        gen_fsm:send_event(self(), {ui, UiEvt})
    end, UiEvts),
    send_orders(S, Orders),
    {next_state, State, S#state{root = Root2}}.

startup(timeout, S = #state{frontend = F}) ->
    {W, H, Bpp} = rdp_server:get_canvas(F),
    Format = case Bpp of
        24 -> rgb24;
        16 -> rgb16_565;
        _ -> error({bad_bpp, Bpp})
    end,
    S2 = S#state{w = W, h = H, bpp = Bpp, format = Format},
    lager:debug("starting session ~px~p @~p bpp (format ~p)", [W, H, Bpp, Format]),
    case rdp_server:get_redir_support(F) of
        false ->
            lager:debug("redir not supported, presenting error screen"),
            no_redir(setup_ui, S2);
        true ->
            {ok, Duo} = duo:start_link(),
            {ok, Nms} = nms:start_link(),
            login(setup_ui, S2#state{duo = Duo, nms = Nms})
    end.

no_redir(setup_ui, S = #state{w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    TopMod = case (H > W) of
        true -> ui_vlayout;
        false -> ui_hlayout
    end,
    Events = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
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
                                     size = {400.0, 18.0*3}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = closebtn,
                                     mod = ui_button,
                                     size = {120.0, 40.0}}} },

        { [{id, logo}],         {init, code:priv_dir(rdpproxy) ++ "/uq-logo.png"} },
        { [{id, banner}],       {init, left, <<"Sorry">>} },
        { [{id, banner}],       {set_bgcolor, UQPurple} },
        { [{id, subtitle}],       {init, left, <<"Redirection not supported">>} },
        { [{id, subtitle}],       {set_bgcolor, UQPurple} },
        { [{id, explain}],      {init, left, <<"It seems that your remote desktop client\n",
                                               "does not support redirection, so it cannot\n",
                                               "be used with EAIT remote lab access.">>} },
        { [{id, explain}],      {set_bgcolor, UQPurple} },
        { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(S, Orders),
    {next_state, no_redir, S#state{root = Root2}};

no_redir({input, F = {Pid,_}, Evt}, S = #state{frontend = {Pid,_}, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(no_redir, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
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

no_redir({ui, {clicked, closebtn}}, S = #state{frontend = F}) ->
    rdp_server:close(F),
    {stop, normal, S}.

login(setup_ui, S = #state{frontend = F, w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    TopMod = case (H > W) of
        true -> ui_vlayout;
        false -> ui_hlayout
    end,
    Events = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
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

        { [{id, logo}],         {init, code:priv_dir(rdpproxy) ++ "/uq-logo.png"} },
        { [{id, banner}],       {init, left, <<"UQ Faculty of EAIT">>} },
        { [{id, banner}],       {set_bgcolor, UQPurple} },
        { [{id, subbanner}],    {init, left, <<"Staff Remote Access">>} },
        { [{id, subbanner}],    {set_bgcolor, UQPurple} },
        { [{id, instru}],       {init, left, <<"Please enter your UQ username and password.">>} },
        { [{id, instru}],       {set_bgcolor, UQPurple} },
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

    {next_state, login, S#state{root = Root3}};

login({input, F = {Pid,_}, Evt}, S = #state{frontend = {Pid,_}}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
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

login({ui, {submitted, userinp}}, S = #state{}) ->
    Event = { [{id, passinp}], focus },
    handle_root_events(login, S, [Event]);

login({ui, {submitted, passinp}}, S = #state{}) ->
    login(check_creds, S);

login({ui, {clicked, loginbtn}}, S = #state{}) ->
    login(check_creds, S);

login(check_creds, S = #state{root = Root, duo = Duo}) ->
    [DefaultDomain | _] = ValidDomains = rdpproxy:config([frontend, domains], [<<".">>]),

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
            Creds = #{username => Username, password => Password},
            case krb_auth:authenticate(Creds) of
                true ->
                    lager:debug("auth for ~p succeeded!", [Username]),
                    S1 = S#state{sess = #session{user = Username, domain = Domain, password = Password}},
                    case duo:preauth(Duo, #{<<"username">> => Username}) of
                        {ok, #{<<"result">> := <<"enroll">>}} ->
                            login(mfa_enroll, S);
                        {ok, #{<<"result">> := <<"allow">>}} ->
                            choose(setup_ui, S1);
                        {ok, #{<<"result">> := <<"auth">>, <<"devices">> := Devs}} ->
                            mfa(setup_ui, S1#state{duodevs = Devs});
                        Else ->
                            lager:debug("duo said: ~p", [Else]),
                            login(invalid_login, S)
                    end;
                false ->
                    lager:debug("auth for ~p failed", [Username]),
                    login(invalid_login, S)
            end
    end;

login(invalid_login, S = #state{}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"Invalid username or password">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, UQPurple} }
    ],
    handle_root_events(login, S, Events);

login(mfa_enroll, S = #state{}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"MFA required but not enrolled">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, UQPurple} }
    ],
    handle_root_events(login, S, Events).

mfa(setup_ui, S = #state{frontend = F, w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    TopMod = case (H > W) of
        true -> ui_vlayout;
        false -> ui_hlayout
    end,
    DuoDevs = S#state.duodevs,
    Events0 = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
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
                                     size = {410.0, H}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = subbanner,
                                     mod = ui_label,
                                     size = {400.0, 36.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = instru,
                                     mod = ui_label,
                                     size = {400.0, 30.0}}} },

        { [{id, logo}],         {init, code:priv_dir(rdpproxy) ++ "/uq-logo.png"} },
        { [{id, subbanner}],    {init, left, <<"Multi-factor Authentication">>} },
        { [{id, subbanner}],    {set_bgcolor, UQPurple} },
        { [{id, instru}],       {init, left, <<"Additional authentication with a device is required.\nPlease choose a device.">>} },
        { [{id, instru}],       {set_bgcolor, UQPurple} }
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
                                                 size = {400.0, 150.0}}} },
                { [{id, {devlyt, Id}}],  init },

                { [{id, {devlyt, Id}}], {add_child,
                                         #widget{id = {devlbllyt, Id},
                                                 mod = ui_vlayout,
                                                 size = {230.0, 150.0}}} },
                { [{id, {devlbllyt, Id}}], init },

                { [{id, {devlbllyt, Id}}],  {add_child,
                                          #widget{id = {devlbl, Id},
                                                  mod = ui_label,
                                                  size = {230.0, 17.0}}} },
                { [{id, {devlbl, Id}}],  {init, left, Name} },
                { [{id, {devlbl, Id}}],  {set_bgcolor, UQPurple} },
                { [{id, {devlbllyt, Id}}],  {add_child,
                                          #widget{id = {devtlbl, Id},
                                                  mod = ui_label,
                                                  size = {230.0, 15.0}}} },
                { [{id, {devtlbl, Id}}],  {init, left, Type} },
                { [{id, {devtlbl, Id}}],  {set_bgcolor, UQPurple} },

                { [{id, {devlyt, Id}}],  {add_child,
                                          #widget{id = {devbtnslyt, Id},
                                                  mod = ui_vlayout,
                                                  size = {170.0, 150.0}}} },
                { [{id, {devbtnslyt, Id}}], init }
            ]
        end,
        Acc2 = case lists:member(<<"push">>, Caps) of
            true ->
                Acc1 ++ [
                    { [{id, {devbtnslyt, Id}}], {add_child,
                                                 #widget{id = {pushbtn, Id},
                                                         mod = ui_button,
                                                         size = {150.0, 30.0}}} },
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
                                                         size = {150.0, 30.0}}} },
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
                                                         size = {150.0, 30.0}}} },
                    { [{id, {callbtn, Id}}],  {init, <<"Phonecall", 0>>} }
                ];
            false -> Acc3
        end,
        Acc5 = case lists:member(<<"mobile_otp">>, Caps) of
            true ->
                Acc4 ++ [
                    { [{id, {devbtnslyt, Id}}], {add_child,
                                                 #widget{id = {otplyt, Id},
                                                         mod = ui_hlayout,
                                                         size = {150.0, 30.0}}} },
                    { [{id, {otplyt, Id}}],      init },
                    { [{id, {otplyt, Id}}], {add_child,
                                                 #widget{id = {otpinp, Id},
                                                         mod = ui_textinput,
                                                         size = {100.0, 30.0}}} },
                    { [{id, {otpinp, Id}}],  {init, <<"code">>} },
                    { [{id, {otplyt, Id}}], {add_child,
                                                 #widget{id = {otpbtn, Id},
                                                         mod = ui_button,
                                                         size = {30.0, 30.0}}} },
                    { [{id, {otpbtn, Id}}],  {init, <<"OK", 0>>} }
                ];
            false -> Acc4
        end
    end, [], DuoDevs),
    {Root3, Orders2, []} = ui:handle_events(Root2, Events1),
    send_orders(S, Orders2),

    {next_state, mfa, S#state{root = Root3}};

mfa({input, F = {Pid,_}, Evt}, S = #state{frontend = {Pid,_}}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(mfa, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
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

mfa({ui, {submitted, {otpinp, DevId}}}, S = #state{root = Root}) ->
    [Txt] = ui:select(Root, [{id, {otpinp, DevId}}]),
    V = ui_textinput:get_text(Txt),
    mfa({submit_otp, DevId, V}, S);
mfa({ui, {clicked, {otpbtn, DevId}}}, S = #state{root = Root}) ->
    [Txt] = ui:select(Root, [{id, {otpinp, DevId}}]),
    V = ui_textinput:get_text(Txt),
    mfa({submit_otp, DevId, V}, S);
mfa({ui, {clicked, {pushbtn, DevId}}}, S = #state{duo = Duo, sess = #session{user = U}}) ->
    Args = #{
        <<"username">> => U,
        <<"factor">> => <<"push">>,
        <<"device">> => DevId,
        <<"async">> => <<"true">>
    },
    case duo:auth(Duo, Args) of
        {ok, #{<<"result">> := <<"deny">>}} ->
            mfa(mfa_deny, S);
        {ok, #{<<"result">> := <<"allow">>}} ->
            choose(setup_ui, S);
        {error, _} ->
            mfa(mfa_deny, S);
        {ok, #{<<"txid">> := TxId}} ->
            mfa_waiting(setup_ui, S#state{duotx = TxId})
    end;
mfa({ui, {clicked, {smsbtn, DevId}}}, S = #state{duo = Duo, sess = #session{user = U}}) ->
    Args = #{
        <<"username">> => U,
        <<"factor">> => <<"sms">>,
        <<"device">> => DevId
    },
    _ = duo:auth(Duo, Args),
    {next_state, mfa, S};
mfa({ui, {clicked, {callbtn, DevId}}}, S = #state{duo = Duo, sess = #session{user = U}}) ->
    Args = #{
        <<"username">> => U,
        <<"factor">> => <<"phone">>,
        <<"device">> => DevId,
        <<"async">> => <<"true">>
    },
    case duo:auth(Duo, Args) of
        {ok, #{<<"result">> := <<"deny">>}} ->
            mfa(mfa_deny, S);
        {ok, #{<<"result">> := <<"allow">>}} ->
            choose(setup_ui, S);
        {error, _} ->
            mfa(mfa_deny, S);
        {ok, #{<<"txid">> := TxId}} ->
            mfa_waiting(setup_ui, S#state{duotx = TxId})
    end;

mfa({submit_otp, DevId, Code}, S = #state{duo = Duo, sess = #session{user = U}}) ->
    Args = #{
        <<"username">> => U,
        <<"factor">> => <<"passcode">>,
        <<"passcode">> => Code
    },
    case duo:auth(Duo, Args) of
        {ok, #{<<"result">> := <<"deny">>}} ->
            mfa(mfa_deny, S);
        {error, _} ->
            mfa(mfa_deny, S);
        {ok, #{<<"result">> := <<"allow">>}} ->
            choose(setup_ui, S)
    end;

mfa(mfa_deny, S = #state{}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"Authentication failed">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, UQPurple} }
    ],
    handle_root_events(mfa, S, Events).

mfa_waiting(setup_ui, S = #state{w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    TopMod = case (H > W) of
        true -> ui_vlayout;
        false -> ui_hlayout
    end,
    Events = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
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
                             #widget{id = explain,
                                     mod = ui_label,
                                     size = {400.0, 18.0*3}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = closebtn,
                                     mod = ui_button,
                                     size = {120.0, 40.0}}} },

        { [{id, logo}],         {init, code:priv_dir(rdpproxy) ++ "/uq-logo.png"} },
        { [{id, banner}],       {init, left, <<"Waiting for Duo">>} },
        { [{id, banner}],       {set_bgcolor, UQPurple} },
        { [{id, explain}],      {init, left, <<"Please check your phone or device\n",
                                               "for a Duo Push prompt or call...\n">>} },
        { [{id, explain}],      {set_bgcolor, UQPurple} },
        { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(S, Orders),
    Fsm = self(),
    #state{duotx = TxId, duo = Duo} = S,
    spawn_link(fun () ->
        mfa_waiter(Fsm, Duo, TxId)
    end),
    {next_state, mfa_waiting, S#state{root = Root2}};

mfa_waiting({input, F = {Pid,_}, Evt}, S = #state{frontend = {Pid,_}, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(mfa_waiting, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
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

mfa_waiting({auth_finished, Result}, S = #state{}) ->
    case Result of
        #{<<"result">> := <<"allow">>} ->
            choose(setup_ui, S);
        _ ->
            mfa(setup_ui, S)
    end;

mfa_waiting({ui, {clicked, closebtn}}, S = #state{frontend = F}) ->
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

choose(setup_ui, S = #state{frontend = F, w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),

    TopMod = case (H > W) of
        true -> ui_vlayout;
        false -> ui_hlayout
    end,
    Events0 = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
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
                                     size = {410.0, H}}} },
        { [{id, loginlyt}], init },
        { [{id, loginlyt}], {add_child,
                             #widget{id = subbanner,
                                     mod = ui_label,
                                     size = {400.0, 36.0}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = instru,
                                     mod = ui_label,
                                     size = {400.0, 15.0}}} },

        { [{id, logo}],         {init, code:priv_dir(rdpproxy) ++ "/uq-logo.png"} },
        { [{id, subbanner}],    {init, left, <<"Which computer?">>} },
        { [{id, subbanner}],    {set_bgcolor, UQPurple} },
        { [{id, instru}],       {init, left, <<"Please choose which computer to connect to:">>} },
        { [{id, instru}],       {set_bgcolor, UQPurple} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events0),
    send_orders(S, Orders),

    #state{nms = Nms, sess = #session{user = U}} = S,
    Devs0 = case nms:get_user_hosts(Nms, U) of
        {ok, D} -> D;
        _ -> []
    end,

    Events1 = lists:foldl(fun (Dev, Acc) ->
        #{<<"hostname">> := Hostname,
          <<"ip">> := Ip} = Dev,
        DescText = case Dev of
            #{<<"building">> := Building, <<"room">> := null} ->
                <<Building/binary, ", unknown room\nIP address: ", Ip/binary>>;
            #{<<"building">> := Building, <<"room">> := Room} ->
                <<Building/binary, ", Room ", Room/binary, "\nIP address: ", Ip/binary>>;
            #{<<"desc">> := Desc} -> Desc
        end,
        Acc ++ [
                { [{id, loginlyt}],     {add_child,
                                         #widget{id = {devlyt, Ip},
                                                 mod = ui_hlayout,
                                                 size = {400.0, 100.0}}} },
                { [{id, {devlyt, Ip}}],  init },

                { [{id, {devlyt, Ip}}], {add_child,
                                         #widget{id = {devlbllyt, Ip},
                                                 mod = ui_vlayout,
                                                 size = {250.0, 100.0}}} },
                { [{id, {devlbllyt, Ip}}], init },

                { [{id, {devlbllyt, Ip}}],  {add_child,
                                          #widget{id = {devlbl, Ip},
                                                  mod = ui_label,
                                                  size = {250.0, 19.0}}} },
                { [{id, {devlbl, Ip}}],  {init, left, Hostname} },
                { [{id, {devlbl, Ip}}],  {set_bgcolor, UQPurple} },
                { [{id, {devlbllyt, Ip}}],  {add_child,
                                          #widget{id = {devtlbl, Ip},
                                                  mod = ui_label,
                                                  size = {240.0, 30.0}}} },
                { [{id, {devtlbl, Ip}}],  {init, left, DescText} },
                { [{id, {devtlbl, Ip}}],  {set_bgcolor, UQPurple} },

                { [{id, {devlyt, Ip}}],  {add_child,
                                          #widget{id = {devbtnslyt, Ip},
                                                  mod = ui_vlayout,
                                                  size = {160.0, 100.0}}} },
                { [{id, {devbtnslyt, Ip}}], init },
                { [{id, {devbtnslyt, Ip}}], {add_child,
                                             #widget{id = {choosebtn, Ip, Hostname},
                                                     mod = ui_button,
                                                     size = {160.0, 30.0}}} },
                { [{id, {choosebtn, Ip, Hostname}}],  {init, <<"Connect to ", Hostname/binary, 0>>} }
        ]
    end, [], Devs0),
    Events2 = case Devs0 of
        [] ->
            Events1 ++ [
                { [{id, instru}],       {set_text, <<"\n">>} },
                { [{id, loginlyt}],     {add_child,
                                         #widget{id = nohostslbl,
                                                 mod = ui_label,
                                                 size = {400.0, 60.0}}} },
                { [{id, nohostslbl}],   {init, left,
                                          <<"Sorry, we have no computers recorded as belonging to your\n"
                                            "user (", U/binary, ").\n\n"
                                            "If you think this is incorrect, please email helpdesk@eait.uq.edu.au.">>} },
                { [{id, nohostslbl}],   {set_bgcolor, UQPurple} },

                { [{id, loginlyt}],     {add_child,
                                         #widget{id = closebtn,
                                                 mod = ui_button,
                                                 size = {120.0, 40.0}}} },
                { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
            ];
        _ -> Events1
    end,
    {Root3, Orders2, []} = ui:handle_events(Root2, Events2),
    send_orders(S, Orders2),

    {next_state, choose, S#state{root = Root3}};

choose({input, F = {Pid,_}, Evt}, S = #state{frontend = {Pid,_}}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(choose, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
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

choose({ui, {clicked, closebtn}}, S = #state{frontend = F}) ->
    rdp_server:close(F),
    {stop, normal, S};

choose({ui, {clicked, {choosebtn, Ip, Hostname}}}, S = #state{nms = Nms, sess = Sess0}) ->
    Sess1 = Sess0#session{host = Ip, port = 3389},
    Ret = nms:wol(Nms, Hostname),
    lager:debug("wol for ~p returned ~p", [Hostname, Ret]),
    waiting(setup_ui, S#state{sess = Sess1}).

waiting(setup_ui, S = #state{w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    TopMod = case (H > W) of
        true -> ui_vlayout;
        false -> ui_hlayout
    end,
    Events = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
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
                             #widget{id = explain,
                                     mod = ui_label,
                                     size = {400.0, 18.0*3}}} },
        { [{id, loginlyt}], {add_child,
                             #widget{id = closebtn,
                                     mod = ui_button,
                                     size = {120.0, 40.0}}} },

        { [{id, logo}],         {init, code:priv_dir(rdpproxy) ++ "/uq-logo.png"} },
        { [{id, banner}],       {init, left, <<"Please wait...">>} },
        { [{id, banner}],       {set_bgcolor, UQPurple} },
        { [{id, explain}],      {init, left, <<"Checking to see if machine is available\n",
                                               "and ready to log you in...\n">>} },
        { [{id, explain}],      {set_bgcolor, UQPurple} },
        { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(S, Orders),
    {ok, AllocPid} = host_alloc_fsm:start(S#state.sess),
    MRef = erlang:monitor(process, AllocPid),
    {next_state, waiting, S#state{root = Root2, allocpid = AllocPid, allocmref = MRef}};

waiting({input, F = {Pid,_}, Evt}, S = #state{frontend = {Pid,_}, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
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

waiting({allocated_session, AllocPid, Sess}, S = #state{frontend = F, allocpid = AllocPid}) ->
    #session{cookie = Cookie} = Sess,
    erlang:demonitor(S#state.allocmref),
    rdp_server:send_redirect(F, Cookie, rdpproxy:config([frontend, hostname], <<"localhost">>)),
    {stop, normal, S};

waiting({'DOWN', MRef, process, _, _}, S = #state{allocmref = MRef}) ->
    {ok, AllocPid} = host_alloc_fsm:start(S#state.sess),
    NewMRef = erlang:monitor(process, AllocPid),
    {next_state, waiting, S#state{allocpid = AllocPid, allocmref = NewMRef}};

waiting({ui, {clicked, closebtn}}, S = #state{frontend = F}) ->
    rdp_server:close(F),
    {stop, normal, S}.

handle_info({'DOWN', MRef, process, _, _}, _State, S = #state{mref = MRef}) ->
    {stop, normal, S};
handle_info(Msg, State, S = #state{}) ->
    ?MODULE:State(Msg, S).

%% @private
terminate(_Reason, _State, #state{duo = undefined, nms = undefined}) ->
    ok;
terminate(_Reason, _State, #state{duo = Duo, nms = Nms}) ->
    duo:stop(Duo),
    nms:stop(Nms),
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
