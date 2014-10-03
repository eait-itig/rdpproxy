%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(db_cookie).
-include("session.hrl").
-include_lib("riakc/include/riakc.hrl").

-export([get/1, new/1, expire/0]).

-define(POOL, riakc_pool).
-define(BUCKET, <<"rdp_cookie">>).
-define(TTL, 8*3600).
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

get(K) ->
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get(C, ?BUCKET, K) of
			{ok, RObj} ->
				case riakc_obj:get_values(RObj) of
					[V] ->
						VRec = decode(V),
						{ok, VRec#session{cookie = K}};
					_ -> {error, conflict}
				end;
			{error, Reason} ->
				{error, Reason}
		end
	end).

new(Session = #session{cookie = auto}) ->
	K = gen_key(),
	Expiry = calendar:datetime_to_gregorian_seconds(erlang:localtime()) + ?TTL,
	RObj0 = riakc_obj:new(?BUCKET, K, encode(Session)),
	MD0 = riakc_obj:get_update_metadata(RObj0),
	MD1 = riakc_obj:set_secondary_index(MD0, [{{integer_index, "expiry"}, [Expiry]}]),
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

