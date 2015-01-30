%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(db_host_meta).
-include_lib("riakc/include/riakc.hrl").

-export([get/1, put/2, find/2]).

-define(POOL, riakc_pool).
-define(BUCKET, <<"rdp_host_meta">>).
-define(IDXS, [
	{"status", [<<"status">>]},
	{"role", [<<"role">>]},
	{"user", [<<"sessions">>, 0, <<"user">>]},
	{"hypervisor", [<<"hypervisor">>]},
	{"updated", integer_index, [<<"updated">>]}
	]).

merge2([{Ts, V}]) -> V;
merge2([{Ts, V} | Rest]) ->
	lists:ukeymerge(1, V, merge2(Rest)).
merge(Vals) ->
	merge2(lists:reverse(lists:sort(decode_vals(Vals)))).

encode_new_val(V0) ->
	V = term_to_binary(lists:usort(V0)),
	{MS, S, _} = os:timestamp(),
	<<MS:44/big, S:20/big, V/binary>>.

decode_vals([]) -> [];
decode_vals([V | Rest]) when is_binary(V) and (byte_size(V) > 0) ->
	<<MS:44/big, S:20/big, Val/binary>> = V,
	[{{MS,S}, binary_to_term(Val)} | decode_vals(Rest)];
decode_vals([V | Rest]) -> decode_vals(Rest).

get(Ip) ->
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get(C, ?BUCKET, Ip) of
			{ok, RObj} ->
				Meta = merge(riakc_obj:get_values(RObj)),
				{ok, Meta};
			{error, Reason} ->
				{error, Reason}
		end
	end).

put(Ip, Meta0) ->
	Now = calendar:datetime_to_gregorian_seconds(erlang:localtime()),
	Meta = jsxd:set([<<"updated">>], Now, Meta0),
	{RObj0, Vs} = poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get(C, ?BUCKET, Ip) of
			{ok, R} ->
				OldVs = riakc_obj:get_values(R),
				NewV = merge([encode_new_val(Meta) | OldVs]),
				{riakc_obj:update_value(R, encode_new_val(NewV)), NewV};
			_ ->
				{riakc_obj:new(?BUCKET, Ip, encode_new_val(Meta)), Meta}
		end
	end),
	%MD0 = riakc_obj:get_update_metadata(RObj0),
	MD0 = dict:new(),
	TwoIdxs = lists:foldl(fun
		({K, Path}, Acc) ->
			case jsxd:get(Path, Vs) of
				{ok, V} when is_binary(V) -> [{{binary_index, K}, [V]} | Acc];
				_ -> Acc
			end;
		({K, Type, Path}, Acc) ->
			case jsxd:get(Path, Vs) of
				{ok, V} -> [{{Type, K}, [V]} | Acc];
				_ -> Acc
			end
	end, [], ?IDXS),
	MD1 = riakc_obj:set_secondary_index(MD0, TwoIdxs),
	RObj = riakc_obj:update_metadata(RObj0, MD1),
	poolboy:transaction(?POOL, fun(C) ->
		riakc_pb_socket:put(C, RObj, [])
	end).

find(Index, Value) ->
	case lists:keyfind(atom_to_list(Index), 1, ?IDXS) of
		{IdxK, Path} -> IdxType = binary_index;
		{IdxK, IdxType, Path} -> ok
	end,
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get_index_eq(C, ?BUCKET, {IdxType, IdxK}, Value) of
			{ok, #index_results_v1{keys = Keys}} ->
				Results = lists:foldl(fun(K, Acc) ->
					case riakc_pb_socket:get(C, ?BUCKET, K) of
						{ok, RObj} ->
							Vs = merge(riakc_obj:get_values(RObj)),
							case jsxd:get(Path, Vs) of
								{ok, Value} -> [{K, Vs} | Acc];
								_ -> Acc
							end;
						_ -> Acc
					end
				end, [], Keys),
				{ok, Results};
			Err ->
				Err
		end
	end).

