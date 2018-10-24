%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
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

-module(ldap_pool).
-behaviour(gen_server).
-behaviour(poolboy_worker).
-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-record(state, {c, fuse, opts}).

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

lookup_ad_ldap(Domain) ->
    Results = inet_res:lookup("_ldap._tcp." ++ Domain, in, srv),
    [Name || {_Prio, _Weight, 389, Name} <- Results].

shuffle(List) ->
    [V || {_,V} <- lists:sort([{crypto:rand_uniform(1,1 bsl 32), V} || V <- List])].

connect(Opts0) ->
    Hosts0 = case lists:keytake(ad_domain, 1, Opts0) of
        {value, {_, Domain}, Opts1} ->
            case lookup_ad_ldap(Domain) of
                [] -> error(no_ad_ldap_servers);
                Other -> Other
            end;
        _ ->
            {value, {_, SetHosts}, Opts1} = lists:keytake(hosts, 1, Opts0),
            SetHosts
    end,
    Fuse = case lists:keytake(fuse, 1, Opts1) of
        {value, F, Opts2} -> F;
        _ -> Opts2 = Opts1, ldap_fuse
    end,
    Hosts = shuffle(Hosts0),
    LdapOptions0 = proplists:get_value(options, Opts2),
    StartTLS = case lists:keytake(starttls, 1, LdapOptions0) of
        {value, {_, V}, TempOpts} ->
            case lists:keytake(sslopts, 1, TempOpts) of
                {value, _, LdapOptions1} -> V;
                _ -> LdapOptions1 = TempOpts, V
            end;
        _ -> LdapOptions1 = LdapOptions0, false
    end,
    Bind = proplists:get_value(bind, Opts2),
    SslOpts = proplists:get_value(sslopts, LdapOptions0, []),
    {ok, C} = connect_retry(Hosts, LdapOptions1, Bind, StartTLS, SslOpts),
    {ok, #state{c = C, opts = Opts0, fuse = Fuse}, 30000}.

connect_retry([Host | Rest], LdapOptions, Bind, StartTLS, SslOpts) ->
    case eldap:open([Host], LdapOptions) of
        {ok, C} ->
            case StartTLS of
               true ->
                   case eldap:start_tls(C, SslOpts, 3000) of
                       ok -> ok;
                       Err -> lager:warning("failed to start LDAP tls with ~p: ~p", [Host, Err])
                   end;
               false -> ok
            end,
            case Bind of
                undefined -> {ok, C};
                [BindDn, Password] ->
                    case eldap:simple_bind(C, BindDn, Password) of
                        ok -> {ok, C};
                        R ->
                            case Rest of [] -> R; _ ->
                                lager:debug("LDAP connection to ~p failed, falling back...", [Host]),
                                connect_retry(Rest, LdapOptions, Bind, StartTLS, SslOpts)
                            end
                    end
            end;
        R = {error, _} ->
            case Rest of [] -> R; _ ->
                lager:debug("LDAP connection to ~p failed, falling back...", [Host]),
                connect_retry(Rest, LdapOptions, Bind, StartTLS, SslOpts)
            end
    end.

init([Opts0]) ->
    Fuse = proplists:get_value(fuse, Opts0, ldap_fuse),
    case fuse:ask(Fuse, sync) of
        ok ->
            try
                connect(Opts0)
            catch error:Err ->
                lager:error("LDAP connection failed: ~p ~p", [Err, erlang:get_stacktrace()]),
                ok = fuse:melt(Fuse),
                {ok, #state{opts = Opts0, fuse = Fuse}, 1000};
            exit:Err ->
                lager:error("LDAP connection failed: ~p ~p", [Err, erlang:get_stacktrace()]),
                ok = fuse:melt(Fuse),
                {ok, #state{opts = Opts0, fuse = Fuse}, 1000}
            end;
        blown -> {ok, #state{opts = Opts0, fuse = Fuse}, 1000}
    end.

handle_call({bind, _Dn, _Password}, _From, #state{c=undefined}=State) ->
    {reply, {error, fuse_blown}, State, 1000};
handle_call({search, _SearchOpts}, _From, #state{c=undefined}=State) ->
    {reply, {error, fuse_blown}, State, 1000};

handle_call({bind, Dn, Password}, From, #state{c=Conn,fuse=F}=State) ->
    case eldap:simple_bind(Conn, Dn, Password) of
        Ret = ok ->
            {reply, Ret, State, 30000};
        Ret when is_tuple(Ret) and (element(1,Ret) =:= ok) ->
            {reply, Ret, State, 30000};
        Ret = {error, Reason} when Reason =:= timeout; Ret =:= ldap_closed ->
            fuse:melt(F),
            gen_server:reply(From, Ret),
            {stop, normal, State};
        Ret = {error, _} ->
            {reply, Ret, State, 30000}
    end;
handle_call({search, SearchOpts}, From, #state{c=Conn,fuse=F}=State) ->
    case eldap:search(Conn, SearchOpts) of
        Ret when is_tuple(Ret) and (element(1,Ret) =:= ok) ->
            {reply, Ret, State, 30000};
        Ret = {error, Reason} when Reason =:= timeout; Ret =:= ldap_closed ->
            fuse:melt(F),
            gen_server:reply(From, Ret),
            {stop, normal, State};
        Ret = {error, _} ->
            {reply, Ret, State, 30000}
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State, 30000}.

handle_cast(_Msg, State) ->
    {noreply, State, 30000}.

handle_info(timeout, #state{c = undefined, fuse =F} = State) ->
    case fuse:ask(F, sync) of
        ok -> {stop, normal, State};
        blown -> {noreply, State, 1000}
    end;
handle_info(timeout, State) ->
    {stop, normal, State};
handle_info(_Info, State) ->
    {noreply, State, 30000}.

terminate(_Reason, #state{c=undefined}) ->
    ok;
terminate(_Reason, #state{c=Conn}) ->
    eldap:close(Conn),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
