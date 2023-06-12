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

-module(ebox_ra).
-behaviour(ra_machine).

-include_lib("ebox/include/ebox.hrl").

-export([init/1, apply/3]).
-export([
    tick/0,
    entries_for_keyid/1,
    entries_for_key/1,
    remember/3,
    remember/4
    ]).
-export([start/0]).
-export([register_metrics/0]).

-type keyid() :: binary().
%% SHA-256 hash of the public key in ssh2 format:
%% <code>crypto:hash(sha256, ssh_file:encode(PubKey, ssh2_pubkey))</code>

-type username() :: binary().

-type pwbox() :: ebox:box().
%% Box containing the user's password

-export_types([keyid/0, username/0, pwbox/0]).

start() ->
    Config = application:get_env(rdpproxy, ra, []),
    Nodes = proplists:get_value(nodes, Config, [node() | nodes()]),
    Servers = [{?MODULE, N} || N <- Nodes],
    ra:start_or_restart_cluster(default,
        ?MODULE_STRING, {module, ?MODULE, #{}}, Servers).

register_metrics() ->
    prometheus_gauge:new([
        {name, ebox_password_cache_entries},
        {help, "Count of entries in the ebox password cache"}]),
    ok.

-spec tick() -> ok.
tick() ->
    T = erlang:system_time(second),
    case ra:process_command(?MODULE, {tick, T}) of
        {ok, Res, _Leader} -> Res;
        Else -> Else
    end.

-spec entries_for_key(ebox:pubkey()) -> {ok, [{username(), pwbox()}]} | {error, term()}.
entries_for_key(PubKey) ->
    KeyId = crypto:hash(sha256, ssh_file:encode(PubKey, ssh2_pubkey)),
    entries_for_keyid(KeyId).

-spec entries_for_keyid(keyid()) -> {ok, [{username(), pwbox()}]} | {error, term()}.
entries_for_keyid(KeyId) ->
    case ra:process_command(?MODULE, {entries_for_key, KeyId}) of
        {ok, Res, _Leader} ->
            case Res of
                {ok, Ents} ->
                    {ok, [{U, ebox:decode(B)} || {U, B} <- Ents]};
                Else -> Else
            end;
        Else -> Else
    end.

-spec remember_pw(ebox:pubkey(), username(), binary()) -> ok | {error, term()}.
remember_pw(PubKey, Username, Password) ->
    Box0 = #ebox_box{unlock_key = PubKey, ciphertext = Password},
    Box1 = ebox:encrypt_box(Box0),
    KeyId = crypto:hash(sha256, ssh_file:encode(PubKey, ssh2_pubkey)),
    remember(KeyId, Username, Box1).

-spec remember(keyid(), username(), pwbox()) -> ok | {error, term()}.
remember(KeyId, User, Box) ->
    Secs = rdpproxy:config([smartcard, pw_cache_lifetime], 7776000),
    remember(Key, Secs).

-spec remember(keyid(), username(), pwbox(), reltime()) -> ok | {error, term()}.
remember(KeyId, User, Box, Secs) ->
    BoxBin = ebox:encode(Box),
    T = erlang:system_time(second) + Secs,
    case ra:process_command(?MODULE, {remember, KeyId, User, BoxBin, T}) of
        {ok, Res, _Leader} -> Res;
        Else -> Else
    end.

-type pw_rec() :: #{expires => time(), pwbox => binary()}.
-type user_recs() :: #{username() => pw_rec()}.
-type time() :: integer().
-type reltime() :: integer().

-record(?MODULE, {
    keys = #{} :: #{keyid() => user_recs()},
    exp = gb_trees:empty() :: gb_trees:tree(time(), [{keyid(), username()}])
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

apply(_Meta, {remember, KeyId, User, BoxBin, TE}, S0 = #?MODULE{keys = K0, exp = HT0}) ->
    U0 = maps:get(KeyId, K0, #{}),
    HT1 = case U0 of
        #{User => #{expires => TE0}} ->
            {value, OldKs0} = gb_trees:lookup(TE0, HT0),
            gb_trees:update(TE0, OldKs0 -- [{KeyId, User}], HT0);
        _ ->
            HT0
    end,
    U1 = U0#{User => #{expires => TE, pwbox => BoxBin}},
    K1 = K0#{KeyId => U1},
    HT2 = case gb_trees:lookup(TE, HT1) of
        none -> gb_trees:insert(TE, [{KeyId, User}], HT1);
        {value, Ks0} -> gb_trees:update(TE, [{KeyId, User} | Ks0], HT1)
    end,
    S1 = S0#?MODULE{keys = K1, exp = HT2},
    {S1, ok, []}.

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

-spec kill_key({keyid(), username()}, #?MODULE{}) -> #?MODULE{}.
kill_key({KeyId, User}, S0 = #?MODULE{keys = K0}) ->
    #{KeyId := U0} = K0,
    U1 = maps:remove(User, U0),
    K1 = K0#{KeyId => U1},
    S0#?MODULE{keys = K1}.
