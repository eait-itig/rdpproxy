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

-module(db_cookie).
-include("session.hrl").
-include_lib("riakc/include/riakc.hrl").

-export([get/1, new/1, expire/0, find/2, delete/1]).

-define(POOL, riakc_pool).
-define(BUCKET, <<"rdp_cookie">>).
-define(ALPHA, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n,$o,$p,$q,$r,$s,$t,$u,$v,$w,$x,$y,$z,$A,$B,$C,$D,$E,$F,$G,$H,$I,$J,$K,$L,$M,$N,$O,$P,$Q,$R,$S,$T,$U,$V,$W,$X,$Y,$Z}).

gen_key(0) -> [];
gen_key(N) ->
    A = ?ALPHA,
    [element(crypto:rand_uniform(1, size(A)+1), A) | gen_key(N - 1)].
gen_key() -> list_to_binary(gen_key(16)).

encode(#session{host=H, port=P, user=U, password=Pw, domain=D}) ->
    HLen = byte_size(H), ULen = byte_size(U),
    PwLen = byte_size(Pw), DLen = byte_size(D),
    <<P:16/big, HLen:16/big, H/binary, ULen:16/big, U/binary, PwLen:16/big, Pw/binary, DLen:16/big, D/binary>>.

decode(<<P:16/big, HLen:16/big, H:HLen/binary, ULen:16/big, U:ULen/binary, PwLen:16/big, Pw:PwLen/binary, DLen:16/big, D:DLen/binary>>) ->
    #session{host = H, port = P, user = U, password = Pw, domain = D}.

get(K) when is_binary(K) and (byte_size(K) > 0) ->
    poolboy:transaction(?POOL, fun(C) ->
        case riakc_pb_socket:get(C, ?BUCKET, K) of
            {ok, RObj} ->
                case riakc_obj:get_values(RObj) of
                    [V] ->
                        VRec = decode(V),
                        MD = riakc_obj:get_metadata(RObj),
                        case riakc_obj:get_secondary_index(MD, {integer_index, "expiry"}) of
                            [Expiry] -> {ok, VRec#session{cookie = K, expiry = Expiry}};
                            _ -> {ok, VRec#session{cookie = K}}
                        end;
                    _ -> {error, conflict}
                end;
            {error, Reason} ->
                {error, Reason}
        end
    end);
get(K) when is_list(K) and (length(K) > 0) -> ?MODULE:get(list_to_binary(K));
get(_) -> {error, not_found}.

delete(K) when is_binary(K) and (byte_size(K) > 0) ->
    poolboy:transaction(?POOL, fun(C) ->
        case riakc_pb_socket:get(C, ?BUCKET, K) of
            {ok, RObj} ->
                riakc_pb_socket:delete_obj(C, RObj);
            {error, Reason} ->
                {error, Reason}
        end
    end).

find(Type, V) when is_list(V) ->
    find(Type, list_to_binary(V));
find(Type, V) ->
    Idx = case Type of
        user -> {binary_index, "user"};
        host -> {binary_index, "host"}
    end,
    poolboy:transaction(?POOL, fun(C) ->
        case riakc_pb_socket:get_index_eq(C, ?BUCKET, Idx, V) of
            {ok, #index_results_v1{keys = Keys}} ->
                Results = lists:foldl(fun(K, Acc) ->
                    case riakc_pb_socket:get(C, ?BUCKET, K) of
                        {ok, RObj} ->
                            Values = riakc_obj:get_values(RObj),
                            Metadatas = riakc_obj:get_metadatas(RObj),
                            lists:foldl(fun({V,MD}, Acc2) ->
                                VRec = decode(V),
                                VRec2 = case riakc_obj:get_secondary_index(MD, {integer_index, "expiry"}) of
                                    [Expiry] -> VRec#session{cookie = K, expiry = Expiry};
                                    _ -> VRec#session{cookie = K}
                                end,
                                [VRec2 | Acc2]
                            end, Acc, lists:zip(Values, Metadatas));
                        _ -> Acc
                    end
                end, [], Keys),
                {ok, Results};
            Err ->
                Err
        end
    end).

new(Session = #session{cookie = auto, user = U, host = H}) ->
    K = gen_key(),
    Expiry = calendar:datetime_to_gregorian_seconds(erlang:localtime()) + ?COOKIE_TTL,
    RObj0 = riakc_obj:new(?BUCKET, K, encode(Session)),
    MD0 = riakc_obj:get_update_metadata(RObj0),
    MD1 = riakc_obj:set_secondary_index(MD0, [
        {{integer_index, "expiry"}, [Expiry]},
        {{binary_index, "user"}, [U]},
        {{binary_index, "host"}, [H]}
    ]),
    RObj = riakc_obj:update_metadata(RObj0, MD1),
    Res = poolboy:transaction(?POOL, fun(C) ->
        riakc_pb_socket:put(C, RObj, [if_none_match])
    end),
    case Res of
        {error, <<"match_found">>} -> new(Session);
        ok -> {ok, K};
        _ -> Res
    end.

expire() ->
    Now = calendar:datetime_to_gregorian_seconds(erlang:localtime()),
    poolboy:transaction(?POOL, fun(C) ->
        case riakc_pb_socket:get_index_range(C, ?BUCKET,
                {integer_index, "expiry"}, 0, Now) of
            {ok, #index_results_v1{keys = Keys}} ->
                Count = lists:foldl(fun(K, Acc) ->
                    case riakc_pb_socket:get(C, ?BUCKET, K) of
                        {ok, RObj} ->
                            riakc_pb_socket:delete_obj(C, RObj),
                            Acc + 1;
                        _ -> Acc
                    end
                end, 0, Keys),
                {ok, Count};
            Err ->
                Err
        end
    end).

