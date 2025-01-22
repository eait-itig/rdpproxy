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

-module(scard_saved_pw_ra).
-behaviour(ra_machine).

-include_lib("public_key/include/public_key.hrl").

-export([init/1, apply/3]).
-export([tick/0, get_user_passwords/1, get_password/1, add_password/2,
    bump_password/1]).
-export([start/0]).
-export([encrypt/2, decrypt/3]).

-export_types([username/0, saved_pw/0]).

-type ra_error() :: {error, term()} | {timeout, ra:server_id()}.

start() ->
    Config = application:get_env(rdpproxy, ra, []),
    Nodes = proplists:get_value(nodes, Config, [node() | nodes()]),
    Servers = [{?MODULE, N} || N <- Nodes],
    ra:start_or_restart_cluster(default,
        ?MODULE_STRING, {module, ?MODULE, #{}}, Servers).

-spec tick() -> ok | ra_error().
tick() ->
    T = erlang:system_time(second),
    case ra:process_command(?MODULE, {tick, T}) of
        {ok, Res, _Leader} -> Res;
        Else -> Else
    end.

-spec bump_password(public_key:pubkey()) -> ok | {error, not_found} | ra_error().
bump_password(PubKey) ->
    Now = erlang:system_time(second),
    Exp = Now + 3600*24*365,
    case ra:process_command(?MODULE, {bump_password, PubKey, Exp}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

-spec get_user_passwords(username()) -> {ok, [encrypted_pw()]} | ra_error().
get_user_passwords(Username) ->
    case ra:process_command(?MODULE, {get_user_passwords, Username}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

-spec get_password(public_key:pubkey()) -> {ok, encrypted_pw()} | {error, not_found} | ra_error().
get_password(PubKey) ->
    case ra:process_command(?MODULE, {get_password, PubKey}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

-spec add_password(username(), encrypted_pw()) -> ok | ra_error().
add_password(Username, EPW) ->
    Now = erlang:system_time(second),
    EPW1 = EPW#{username => Username,
                created => Now,
                expires => Now + 3600*24*365},
    case ra:process_command(?MODULE, {add_password, EPW1}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

-type username() :: binary().
-type password() :: binary().
-type time() :: integer().
-type reltime() :: integer().

-type encrypted_pw() :: #{
    username => username(),
    public_key => public_key:pubkey(),
    ephem_public_key => public_key:pubkey(),
    nonce => binary(),
    iv => binary(),
    edata => binary(),
    mac => binary(),
    created => time(),
    expires => time()
    }.

-spec encrypt(password(), public_key:pubkey()) -> encrypted_pw().
encrypt(Pw, {PubKeyPt = #'ECPoint'{point = PubKeyPtBin}, Curve} = PubKey) ->
    EphemKey = public_key:generate_key(Curve),
    #'ECPrivateKey'{publicKey = EphemPubKeyPtBin} = EphemKey,
    EphemPubKeyPt = #'ECPoint'{point = EphemPubKeyPtBin},
    Nonce = crypto:strong_rand_bytes(16),
    ECDHSecret = public_key:compute_key(PubKeyPt, EphemKey),
    EncKey = crypto:hash(sha256, [<<"SCARD_SAVED_PW_ENC">>, 0,
        <<(byte_size(Nonce)):32/big>>, Nonce,
        <<(byte_size(ECDHSecret)):32/big>>, ECDHSecret]),
    MacKey = crypto:hash(sha256, [<<"SCARD_SAVED_PW_MAC">>, 0,
        <<(byte_size(Nonce)):32/big>>, Nonce,
        <<(byte_size(ECDHSecret)):32/big>>, ECDHSecret]),
    IV = crypto:strong_rand_bytes(16),
    EData = crypto:crypto_one_time(chacha20, EncKey, IV, Pw, true),
    Mac = crypto:mac(hmac, sha256, MacKey, [PubKeyPtBin, EData]),
    #{
        public_key => PubKey,
        ephem_public_key => {EphemPubKeyPt, Curve},
        nonce => Nonce,
        iv => IV,
        edata => EData,
        mac => Mac
    }.

-spec decrypt(encrypted_pw(), pid(), nist_piv:slot()) -> {ok, password()} | {error, term()}.
decrypt(EPW, Piv, Slot) ->
    #{public_key := PubKey, ephem_public_key := EphemPubKey, nonce := Nonce,
      iv := IV, edata := EData, mac := Mac} = EPW,
    Algo = nist_piv:algo_for_key(PubKey),
    {#'ECPoint'{point = PubKeyPtBin}, Curve} = PubKey,
    {EphemPubPt, Curve} = EphemPubKey,
    case apdu_transform:command(Piv, {ecdh, Slot, Algo, EphemPubPt}) of
        {ok, [{ok, ECDHSecret}]} ->
            EncKey = crypto:hash(sha256, [<<"SCARD_SAVED_PW_ENC">>, 0,
                <<(byte_size(Nonce)):32/big>>, Nonce,
                <<(byte_size(ECDHSecret)):32/big>>, ECDHSecret]),
            MacKey = crypto:hash(sha256, [<<"SCARD_SAVED_PW_MAC">>, 0,
                <<(byte_size(Nonce)):32/big>>, Nonce,
                <<(byte_size(ECDHSecret)):32/big>>, ECDHSecret]),
            OurMac = crypto:mac(hmac, sha256, MacKey, [PubKeyPtBin, EData]),
            case crypto:hash_equals(OurMac, Mac) of
                true ->
                    Data = crypto:crypto_one_time(chacha20, EncKey, IV, EData, false),
                    {ok, Data};
                false ->
                    {error, bad_mac}
            end;
        {ok, [Ret]} -> Ret;
        Err -> Err
    end.

-record(?MODULE, {
    pws = #{} :: #{public_key:pubkey() => encrypted_pw()},
    exp = gb_trees:empty() :: gb_trees:tree(time(), [public_key:pubkey()]),
    last_time :: time()
    }).

init(_Config) ->
    #?MODULE{}.

apply(#{index := Idx}, {tick, T}, S0 = #?MODULE{}) ->
    S1 = expire_pws(T, S0),
    S2 = S1#?MODULE{last_time = T},
    {S2, ok, [{release_cursor, Idx, S1}]};

apply(_Meta, {get_password, PubKey}, S0 = #?MODULE{pws = P0}) ->
    case P0 of
        #{PubKey := EPW} ->
            {S0, {ok, EPW}, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {bump_password, PubKey, T1}, S0 = #?MODULE{pws = P0, exp = E0}) ->
    case P0 of
        #{PubKey := EPW0} ->
            #{expires := T0} = EPW0,
            EPW1 = EPW0#{expires => T1},
            OldKs0 = gb_trees:get(T0, E0),
            OldKs1 = OldKs0 -- [PubKey],
            E1 = case OldKs1 of
                [] -> gb_trees:delete(T0, E0);
                _ -> gb_trees:update(T0, OldKs1, E0)
            end,
            E2 = case gb_trees:lookup(T1, E1) of
                none -> gb_trees:insert(T1, [PubKey], E1);
                {value, Ks0} -> gb_trees:update(T1, [PubKey | Ks0], E1)
            end,
            P1 = P0#{PubKey => EPW1},
            S1 = S0#?MODULE{pws = P1, exp = E2},
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {get_user_passwords, Username}, S0 = #?MODULE{pws = P0}) ->
    Results = lists:filter(fun
        (#{username := U}) when U =:= Username -> true;
        (_) -> false
    end, maps:values(P0)),
    {S0, {ok, Results}, []};

apply(#{index := Idx}, {add_password, EPW}, S0 = #?MODULE{pws = P0, exp = E0}) ->
    #{public_key := PubKey, expires := Expiry} = EPW,
    P1 = P0#{PubKey => EPW},
    E1 = case gb_trees:lookup(Expiry, E0) of
        none -> gb_trees:insert(Expiry, [PubKey], E0);
        {value, Ks0} -> gb_trees:update(Expiry, [PubKey | Ks0], E0)
    end,
    S1 = S0#?MODULE{pws = P1, exp = E1},
    {S1, ok, [{release_cursor, Idx, S1}]}.

expire_pws(T, S0 = #?MODULE{exp = HT0}) ->
    case gb_trees:is_empty(HT0) of
        true -> S0;
        false ->
            {TE, Keys, HT1} = gb_trees:take_smallest(HT0),
            if
                (T > TE) ->
                    S1 = S0#?MODULE{exp = HT1},
                    S2 = lists:foldl(fun kill_key/2, S1, Keys),
                    expire_pws(T, S2);
                true ->
                    S0
            end
    end.

-spec kill_key(public_key:pubkey(), #?MODULE{}) -> #?MODULE{}.
kill_key(K, S0 = #?MODULE{pws = K0}) ->
    K1 = maps:remove(K, K0),
    S0#?MODULE{pws = K1}.
