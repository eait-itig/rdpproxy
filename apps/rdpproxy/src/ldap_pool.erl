%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ldap_pool).
-behaviour(gen_server).
-behaviour(poolboy_worker).
-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-record(state, {c}).

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

lookup_ad_ldap(Domain) ->
    Results = inet_res:lookup("_ldap._tcp." ++ Domain, in, srv),
    [Name || {_Prio, _Weight, 389, Name} <- Results].

init([Opts0]) ->
    Hosts = case lists:keytake(ad_domain, 1, Opts0) of
        {value, {_, Domain}, Opts1} ->
            case lookup_ad_ldap(Domain) of
                [] -> error(no_ad_ldap_servers);
                Other -> Other
            end;
        _ ->
            {value, {_, SetHosts}, Opts1} = lists:keytake(hosts, 1, Opts0),
            SetHosts
    end,
    LdapOptions0 = proplists:get_value(options, Opts1),
    StartTLS = case lists:keytake(starttls, 1, LdapOptions0) of
        {value, {_, V}, TempOpts} ->
            case lists:keytake(sslopts, 1, TempOpts) of
                {value, _, LdapOptions1} -> V;
                _ -> LdapOptions1 = TempOpts, V
            end;
        _ -> LdapOptions1 = LdapOptions0, false
    end,
    lager:info("opening ldap to ~p (options = ~p)", [Hosts, LdapOptions1]),
    {ok, C} = eldap:open(Hosts, LdapOptions1),
    case StartTLS of
        true ->
            case eldap:start_tls(C, proplists:get_value(sslopts, LdapOptions0, []), 3000) of
                ok -> ok;
                Err -> lager:warning("failed to start LDAP tls with ~p: ~p", [Hosts, Err])
            end;
        false -> ok
    end,
	{ok, #state{c = C}, 30000}.

handle_call({bind, Dn, Password}, _From, #state{c=Conn}=State) ->
    {reply, eldap:simple_bind(Conn, Dn, Password), State, 30000};
handle_call({search, SearchOpts}, _From, #state{c=Conn}=State) ->
    {reply, eldap:search(Conn, SearchOpts), State, 30000};
handle_call(_Request, _From, State) ->
    {reply, ok, State, 30000}.

handle_cast(_Msg, State) ->
    {noreply, State, 30000}.

handle_info(timeout, State) ->
    {stop, normal, State};
handle_info(_Info, State) ->
    {noreply, State, 30000}.

terminate(_Reason, #state{c=Conn}) ->
    eldap:close(Conn),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
