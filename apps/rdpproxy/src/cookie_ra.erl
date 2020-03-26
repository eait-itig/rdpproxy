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

-module(cookie_ra).
-include("session.hrl").
-behaviour(ra_machine).

-export([init/1, apply/3]).
-export([create/1, get/1, expire/0, list/0]).
-export([start/0]).
-export([session_id/1, gen_key/0]).

-define(ALPHA, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n,$o,$p,$q,$r,$s,$t,$u,$v,$w,$x,$y,$z,$A,$B,$C,$D,$E,$F,$G,$H,$I,$J,$K,$L,$M,$N,$O,$P,$Q,$R,$S,$T,$U,$V,$W,$X,$Y,$Z}).

gen_key(0) -> [];
gen_key(N) ->
    A = ?ALPHA,
    [element(crypto:rand_uniform(1, size(A)+1), A) | gen_key(N - 1)].
gen_key() -> list_to_binary(gen_key(16)).

session_id(#session{cookie = Ck, user = U, password = Pw}) ->
    RiakConfig = application:get_env(rdpproxy, ra, []),
    KeyList = proplists:get_value(keys, RiakConfig),
    {KeyRef, KeyNum} = lists:last(KeyList),
    <<_:1, Id:31/big>> = crypto:hmac(sha256,
        <<Ck/binary, U/binary, Pw/binary>>, <<KeyNum:128/big>>, 4),
    Id.

encode(#session{host=H, expiry=E, port=P, user=U, password=Pw, domain=D}) ->
    HLen = byte_size(H), ULen = byte_size(U),
    PwLen = byte_size(Pw), DLen = byte_size(D),
    RiakConfig = application:get_env(rdpproxy, ra, []),
    case proplists:get_value(keys, RiakConfig) of
        undefined ->
            <<P:16/big, E:64/big, HLen:16/big, H/binary, ULen:16/big, U/binary,
              PwLen:16/big, Pw/binary, DLen:16/big, D/binary>>;
        KeyList ->
            {KeyRef, KeyNum} = lists:last(KeyList),
            Iv = crypto:strong_rand_bytes(16),
            Key = <<KeyNum:128/big>>,
            PadLen = 16 - (PwLen rem 16),
            PwPad = <<Pw/binary, PadLen:PadLen/big-unit:8>>,
            PwEnc = crypto:block_encrypt(aes_cbc128, Key, Iv, PwPad),
            PwMac = crypto:hmac(sha256, Key, <<H/binary, U/binary, PwEnc/binary>>),
            IvLen = byte_size(Iv), PwEncLen = byte_size(PwEnc),
            PwMacLen = byte_size(PwMac),
            <<P:16/big, E:64/big,
              HLen:16/big, H/binary,
              ULen:16/big, U/binary,
              KeyRef:16/big,
              IvLen:16/big, Iv/binary,
              PwEncLen:16/big, PwEnc/binary,
              PwMacLen:16/big, PwMac/binary,
              DLen:16/big, D/binary>>
    end.

decode(<<P:16/big, E:64/big, HLen:16/big, H:HLen/binary, ULen:16/big, U:ULen/binary,
         KeyRef:16/big, IvLen:16/big, Iv:IvLen/binary,
         PwEncLen:16/big, PwEnc:PwEncLen/binary,
         PwMacLen:16/big, PwMac:PwMacLen/binary, DLen:16/big, D:DLen/binary>>) ->
    RiakConfig = application:get_env(rdpproxy, ra, []),
    KeyList = proplists:get_value(keys, RiakConfig),
    KeyNum = proplists:get_value(KeyRef, KeyList),
    Key = <<KeyNum:128/big>>,
    OurPwMac = crypto:hmac(sha256, Key, <<H/binary, U/binary, PwEnc/binary>>),
    OurPwMac = PwMac,
    PwPad = crypto:block_decrypt(aes_cbc128, Key, Iv, PwEnc),
    PadLen = binary:last(PwPad), PwLen = byte_size(PwPad) - PadLen,
    <<Pw:PwLen/binary, PadLen:PadLen/big-unit:8>> = PwPad,
    #session{expiry = E, host = H, port = P, user = U, password = Pw, domain = D};
decode(<<P:16/big, E:64/big, HLen:16/big, H:HLen/binary, ULen:16/big, U:ULen/binary,
         PwLen:16/big, Pw:PwLen/binary, DLen:16/big, D:DLen/binary>>) ->
    #session{host = H, expiry = E, port = P, user = U, password = Pw, domain = D}.

create(S = #session{}) ->
    Cookie = gen_key(),
    S1 = S#session{expiry = erlang:system_time(second) + ?COOKIE_TTL},
    S2 = S1#session{cookie = Cookie},
    case ra:process_command(cookie_ra, {create, Cookie, encode(S2)}) of
        {ok, {error, duplicate_key}, _Leader} -> create(S);
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get(K) ->
    case ra:process_command(cookie_ra, {get, K}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

expire() ->
    Now = erlang:system_time(second),
    case ra:process_command(cookie_ra, {expire, Now}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

list() ->
    case ra:process_command(cookie_ra, list) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

start() ->
    Config = application:get_env(rdpproxy, ra, []),
    Nodes = proplists:get_value(nodes, Config, [node() | nodes()]),
    Servers = [{cookie_ra, N} || N <- Nodes],
    ra:start_or_restart_cluster("cookie_ra", {module, ?MODULE, #{}}, Servers).

-record(state, {lookup = #{}, expireq = queue:new()}).

expire_keys(Now, S0 = #state{lookup = L0, expireq = EQ0}) ->
    case queue:out(EQ0) of
        {{value, Key}, EQ1} ->
            case L0 of
                #{Key := Bin} ->
                    #session{expiry = Exp} = decode(Bin),
                    if
                        (Exp =< Now) ->
                            L1 = maps:remove(Key, L0),
                            S1 = S0#state{lookup = L1, expireq = EQ1},
                            expire_keys(Now, S1);
                        true -> S0
                    end;
                _ -> S0
            end;
        _ -> S0
    end.

init(_Config) ->
    #state{}.

apply(#{index := Idx}, {create, Se0 = #session{cookie = Key}}, S0 = #state{lookup = L0, expireq = EQ0}) ->
    case L0 of
        #{Key := _} ->
            {S0, {error, duplicate_key}, []};
        _ ->
            Se1 = Se0#session{cookie = Key},
            L1 = L0#{Key => encode(Se1)},
            EQ1 = queue:in(Key, EQ0),
            S1 = S0#state{lookup = L1, expireq = EQ1},
            Effects = case Idx rem 1000 of
                0 -> [{release_cursor, Idx, S1}];
                _ -> []
            end,
            {S1, {ok, Key}, Effects}
    end;

apply(#{index := Idx}, {create, Key, SeBin}, S0 = #state{lookup = L0, expireq = EQ0}) ->
    case L0 of
        #{Key := _} ->
            {S0, {error, duplicate_key}, []};
        _ ->
            L1 = L0#{Key => SeBin},
            EQ1 = queue:in(Key, EQ0),
            S1 = S0#state{lookup = L1, expireq = EQ1},
            Effects = case Idx rem 100 of
                0 -> [{release_cursor, Idx, S1}];
                _ -> []
            end,
            {S1, {ok, Key}, Effects}
    end;

apply(_Meta, {get, Key}, S0 = #state{lookup = L0}) ->
    case L0 of
        #{Key := SeBin} ->
            Se0 = decode(SeBin),
            {S0, {ok, Se0#session{cookie = Key}}, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(#{index := Idx}, {expire, Now}, S0 = #state{lookup = L0, expireq = EQ0}) ->
    S1 = expire_keys(Now, S0),
    Effects = case Idx rem 100 of
        0 -> [{release_cursor, Idx, S1}];
        _ -> []
    end,
    {S1, ok, Effects};

apply(_Meta, list, S0 = #state{lookup = L}) ->
    List = maps:fold(fun (K, V, Acc) ->
        Sess = decode(V),
        Sess1 = Sess#session{cookie = K, password = redacted},
        [Sess1 | Acc]
    end, [], L),
    {S0, {ok, List}, []}.
