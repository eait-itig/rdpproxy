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

lookup_ad_ldaps(Domain) ->
    Results = inet_res:lookup("_ldaps._tcp." ++ Domain, in, srv),
    [Name || {_Prio, _Weight, 636, Name} <- Results].
lookup_ad_ldap(Domain) ->
    Results = inet_res:lookup("_ldap._tcp." ++ Domain, in, srv),
    [Name || {_Prio, _Weight, 389, Name} <- Results].

init([Opts0]) ->
    Hosts = case lists:keytake(ad_domain, 1, Opts0) of
        {value, {_, Domain}, Opts1} ->
            case lookup_ad_ldaps(Domain) of
                [] -> lookup_ad_ldap(Domain);
                Other -> Other
            end;
        _ ->
            {value, {_, SetHosts}, Opts1} = lists:keytake(hosts, 1, Opts0),
            SetHosts
    end,
    {ok, C} = eldap:open(Hosts, Opts1),
	{ok, #state{c = C}}.

handle_call({bind, Dn, Password}, _From, #state{c=Conn}=State) ->
    {reply, eldap:simple_bind(Conn, Dn, Password), State};
handle_call({search, SearchOpts}, _From, #state{c=Conn}=State) ->
    {reply, eldap:search(Conn, SearchOpts), State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{c=Conn}) ->
    ok = eldap:close(Conn),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
