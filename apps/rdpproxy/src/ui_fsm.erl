%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
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

-record(state, {frontend, mref, w, h, bpp, root, sess}).

%% @private
init([Frontend]) ->
    gen_fsm:send_event(Frontend, {subscribe, self()}),
    MRef = monitor(process, Frontend),
    {ok, startup, #state{mref = MRef, frontend = Frontend}, 0}.

send_orders(F, Orders) ->
    lists:foreach(fun(U) ->
        gen_fsm:send_event(F, {send_update, U})
    end, ui:orders_to_updates(Orders)).

handle_root_events(State, S = #state{frontend = F, root = Root}, Events) ->
    {Root2, Orders, UiEvts} = ui:handle_events(Root, Events),
    lists:foreach(fun(UiEvt) ->
        gen_fsm:send_event(self(), {ui, UiEvt})
    end, UiEvts),
    send_orders(F, Orders),
    {next_state, State, S#state{root = Root2}}.

startup(timeout, S = #state{frontend = F}) ->
    {W, H, Bpp} = gen_fsm:sync_send_event(F, get_canvas),
    S2 = S#state{w = W, h = H, bpp = Bpp},
    case gen_fsm:sync_send_event(F, get_redir_support) of
        false ->
            no_redir(setup_ui, S2);
        true ->
            login(setup_ui, S2)
    end.

no_redir(setup_ui, S = #state{frontend = F, w = W, h = H, bpp = _Bpp}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}),
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
        { [{id, banner}],       {init, left, <<"Sorry">>} },
        { [{id, banner}],       {set_bgcolor, UQPurple} },
        { [{id, explain}],      {init, left, <<"It seems that your remote desktop client\n",
                                               "does not support redirection, so it cannot\n",
                                               "be used with EAIT remote lab access.">>} },
        { [{id, explain}],      {set_bgcolor, UQPurple} },
        { [{id, closebtn}],     {init, <<"Disconnect", 0>>} }
    ],
    {Root2, Orders, []} = ui:handle_events(Root, Events),
    send_orders(F, Orders),
    {next_state, no_redir, S#state{root = Root2}};

no_redir({input, F, Evt}, S = #state{frontend = F, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(no_redir, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            gen_fsm:send_event(F, close),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(no_redir, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(no_redir, S, [Event]);
        _ ->
            {next_state, no_redir, S}
    end;

no_redir({ui, {clicked, closebtn}}, S = #state{frontend = F}) ->
    gen_fsm:send_event(F, close),
    {stop, normal, S}.

login(setup_ui, S = #state{frontend = F, w = W, h = H}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}),
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
    send_orders(F, Orders),

    {_Autologon, U, _D, P} = gen_fsm:sync_send_event(F, get_autologon),
    Events2 = [
        { [{id, userinp}], {set_text, U} },
        { [{id, passinp}], {set_text, P} }
    ] ++ if (byte_size(U) > 0) ->
        [ { [{id, passinp}], focus } ];
    true -> []
    end,

    {Root3, Orders2, []} = ui:handle_events(Root2, Events2),
    send_orders(F, Orders2),

    {next_state, login, S#state{root = Root3}};

login({input, F, Evt}, S = #state{frontend = F}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            gen_fsm:send_event(F, close),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(login, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
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

login(check_creds, S = #state{frontend = F, root = Root}) ->
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
            login(invalid_login, S);
        {_, <<>>} ->
            login(invalid_login, S);
        _ ->
            waiting(setup_ui, S#state{sess =
                #session{user = Username, domain = Domain, password = Password}})
    end;

login(invalid_login, S = #state{}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    LightRed = {1.0, 0.8, 0.8},
    Events = [
        { [{id, loginlyt}], {remove_child, {id, badlbl}} },
        { [{id, loginlyt}], {add_child, {before, {id, loginbtn}},
            #widget{id = badlbl, mod = ui_label, size = {400.0, 15.0}}
            } },
        { [{id, badlbl}],   {init, center, <<"Username and password are both required">>} },
        { [{id, badlbl}],   {set_fgcolor, LightRed} },
        { [{id, badlbl}],   {set_bgcolor, UQPurple} }
    ],
    handle_root_events(login, S, Events).

waiting(setup_ui, S = #state{frontend = F, w = W, h = H, bpp = _Bpp}) ->
    UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
    {Root, _, []} = ui:new({float(W), float(H)}),
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
    send_orders(F, Orders),
    {ok, _} = timer:send_after(500, find_machine),
    {next_state, waiting, S#state{root = Root2}};

waiting({input, F, Evt}, S = #state{frontend = F, root = _Root}) ->
    case Evt of
        #ts_inpevt_mouse{point = P} ->
            Event = { [{contains, P}], Evt },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_key{code = esc, action = down} ->
            gen_fsm:send_event(F, close),
            {stop, normal, S};
        #ts_inpevt_key{code = tab, action = down} ->
            Event = { [{id, root}], focus_next },
            handle_root_events(waiting, S, [Event]);
        #ts_inpevt_key{code = _Code} ->
            Event = { [{tag, focus}], Evt },
            handle_root_events(waiting, S, [Event]);
        _ ->
            {next_state, waiting, S}
    end;

waiting(find_machine, S = #state{sess = Sess, frontend = F}) ->
    case db_user_status:get(Sess#session.user) of
        {ok, Ip} ->
            {ok, Cookie} = db_cookie:new(Sess#session{
                host = Ip, port = 3389}),
            gen_fsm:send_event(F, {redirect,
                Cookie, rdpproxy:config([frontend, hostname], <<"localhost">>),
                Sess#session.user, Sess#session.domain, Sess#session.password}),
            {stop, normal, S};

        _ ->
            case db_host_status:find(<<"available">>) of
                {ok, [Ip | _]} ->
                    {ok, Cookie} = db_cookie:new(Sess#session{
                        host = Ip, port = 3389}),
                    gen_fsm:send_event(F, {redirect,
                        Cookie, rdpproxy:config([frontend, hostname], <<"localhost">>),
                        Sess#session.user, Sess#session.domain, Sess#session.password}),
                    {stop, normal, S};
                _ ->
                    {ok, _} = timer:send_after(500, find_machine),
                    {next_state, waiting, S}
            end
    end;

waiting({ui, {clicked, closebtn}}, S = #state{frontend = F}) ->
    gen_fsm:send_event(F, close),
    {stop, normal, S}.

handle_info(find_machine, State, S = #state{}) ->
    ?MODULE:State(find_machine, S);

handle_info({'DOWN', MRef, process, _, _}, _State, S = #state{mref = MRef}) ->
    {stop, normal, S}.

%% @private
terminate(_Reason, _State, _Data) ->
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
