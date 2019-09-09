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
-export([startup/2, login/2, no_redir/2, waiting/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid()) -> {ok, pid()}.
start_link(Frontend) ->
    gen_fsm:start_link(?MODULE, [Frontend], []).

-record(state, {frontend, mref, w, h, bpp, format, root, sess, allocpid, allocmref}).

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
            login(setup_ui, S2)
    end.

no_redir(setup_ui, S = #state{w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    Events = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = ui_hlayout}} },
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
    Events = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = ui_hlayout}} },
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
        { [{id, subbanner}],    {init, left, <<"Remote Lab Access">>} },
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

login(check_creds, S = #state{root = Root}) ->
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
            Creds = [{<<"username">>, Username}, {<<"password">>, Password}],
            case ldap_auth:process(rdpproxy:config(ldap, []), Creds) of
                {true, _} ->
                    lager:debug("auth for ~p succeeded!", [Username]),
                    waiting(setup_ui, S#state{sess =
                        #session{user = Username, domain = Domain, password = Password}});
                {false, _} ->
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
    handle_root_events(login, S, Events).

waiting(setup_ui, S = #state{w = W, h = H, format = Fmt}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}, Fmt),
    Events = [
        { [{id, root}],     {set_bgcolor, UQPurple} },
        { [{id, root}],     {add_child,
                             #widget{id = hlayout,
                                     mod = ui_hlayout}} },
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
        { [{id, explain}],      {init, left, <<"We're busy finding an available virtual lab\n",
                                               "machine to log you in...\n">>} },
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
terminate(_Reason, _State, _Data) ->
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
