%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>
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

-module(remember_ra).
-behaviour(ra_machine).

-export([init/1, apply/3]).
-export([tick/0, check/1, remember/1, remember/2]).
-export([start/0]).
-export([register_metrics/0]).

-export_types([duoid/0, username/0]).

start() ->
    Config = application:get_env(rdpproxy, ra, []),
    Nodes = proplists:get_value(nodes, Config, [node() | nodes()]),
    Servers = [{?MODULE, N} || N <- Nodes],
    ra:start_or_restart_cluster(default,
        ?MODULE_STRING, {module, ?MODULE, #{}}, Servers).

register_metrics() ->
    prometheus_gauge:new([
        {name, duo_remember_cache_entries},
        {help, "Count of entries in the duo 'remember me' cache"}]),
    ok.

-spec tick() -> ok.
tick() ->
    T = erlang:system_time(second),
    case ra:process_command(?MODULE, {tick, T}) of
        {ok, Res, _Leader} -> Res;
        Else -> Else
    end.

-spec check(key()) -> true | false.
check(Key) ->
    case ra:process_command(?MODULE, {check, Key}) of
        {ok, Res, _Leader} -> Res;
        Else -> Else
    end.

-spec remember(key()) -> ok.
remember(Key) ->
    Secs = rdpproxy:config([duo, remember_time], 36000),
    remember(Key, Secs).

-spec remember(key(), reltime()) -> ok.
remember(Key, Secs) ->
    T = erlang:system_time(second) + Secs,
    case ra:process_command(?MODULE, {remember, Key, T}) of
        {ok, Res, _Leader} -> Res;
        Else -> Else
    end.

-type duoid() :: binary().
-type username() :: binary().
-type key() :: {duoid(), username()}.
-type time() :: integer().
-type reltime() :: integer().

-record(?MODULE, {
    keys = #{} :: #{key() => boolean()},
    exp = gb_trees:empty() :: gb_trees:tree(time(), [key()])
    }).

init(_Config) ->
    #?MODULE{}.

apply(#{index := Idx}, {tick, T}, S0 = #?MODULE{}) ->
    S1 = expire_keys(T, S0),
    prometheus_gauge:set(duo_remember_cache_entries, maps:size(S1#?MODULE.keys)),
    {S1, ok, [{release_cursor, Idx, S1}]};

apply(_Meta, {check, Key}, S0 = #?MODULE{keys = K0}) ->
    case K0 of
        #{Key := true} -> {S0, true, []};
        _ -> {S0, false, []}
    end;

apply(_Meta, {remember, Key, TE}, S0 = #?MODULE{keys = K0, exp = HT0}) ->
    case K0 of
        #{Key := true} ->
            {S0, ok, []};
        _ ->
            K1 = K0#{Key => true},
            HT1 = case gb_trees:lookup(TE, HT0) of
                none -> gb_trees:insert(TE, [Key], HT0);
                {value, Ks0} -> gb_trees:update(TE, [Key | Ks0], HT0)
            end,
            S1 = S0#?MODULE{keys = K1, exp = HT1},
            {S1, ok, []}
    end.

expire_keys(T, S0 = #?MODULE{exp = HT0}) ->
    case gb_trees:is_empty(HT0) of
        true -> S0;
        false ->
            {TE, Keys, HT1} = gb_trees:take_smallest(HT0),
            if
                (T > TE) ->
                    S1 = S0#?MODULE{exp = HT1},
                    S2 = lists:foldl(fun kill_key/2, S1, Keys),
                    expire_keys(T, S2);
                true ->
                    S0
            end
    end.

-spec kill_key(key(), #?MODULE{}) -> #?MODULE{}.
kill_key(K, S0 = #?MODULE{keys = K0}) ->
    K1 = maps:remove(K, K0),
    S0#?MODULE{keys = K1}.
