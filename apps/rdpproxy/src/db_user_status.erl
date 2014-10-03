%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(db_user_status).
-include_lib("riakc/include/riakc.hrl").

-export([get/1, put/2, find/1, clear/1]).

-define(POOL, riakc_pool).
-define(BUCKET, <<"rdp_user_status">>).

merge(Vals) ->
	[{_Ts,V} | _] = lists:reverse(lists:sort(decode_vals(Vals))),
	V.

encode_new_val(V) when is_binary(V) ->
	{MS, S, _} = os:timestamp(),
	<<MS:44/big, S:20/big, V/binary>>.

decode_vals([]) -> [];
decode_vals([V | Rest]) when is_binary(V) ->
	<<MS:44/big, S:20/big, Val/binary>> = V,
	[{{MS,S}, Val} | decode_vals(Rest)].

get(User) ->
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get(C, ?BUCKET, User) of
			{ok, RObj} ->
				Ip = merge(riakc_obj:get_values(RObj)),
				{ok, Ip};
			{error, Reason} ->
				{error, Reason}
		end
	end).

put(User, Ip) ->
	RObj0 = poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get(C, ?BUCKET, User) of
			{ok, R} -> riakc_obj:update_value(R, encode_new_val(Ip));
			_ -> riakc_obj:new(?BUCKET, User, encode_new_val(Ip))
		end
	end),
	MD0 = riakc_obj:get_update_metadata(RObj0),
	MD1 = riakc_obj:set_secondary_index(MD0, [{{binary_index, "ip"}, [Ip]}]),
	RObj = riakc_obj:update_metadata(RObj0, MD1),
	poolboy:transaction(?POOL, fun(C) ->
		riakc_pb_socket:put(C, RObj, [])
	end).

clear(Ip) ->
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get_index_eq(C, ?BUCKET, {binary_index, "ip"}, Ip) of
			{ok, #index_results_v1{keys = Keys}} ->
				Count = lists:foldl(fun(K, Acc) ->
					case riakc_pb_socket:get(C, ?BUCKET, K) of
						{ok, RObj} ->
							case merge(riakc_obj:get_values(RObj)) of
								Ip ->
									riakc_pb_socket:delete_obj(C, RObj),
									Acc + 1;
								_ -> Acc
							end;
						_ -> Acc
					end
				end, 0, Keys),
				{ok, Count};
			Err ->
				Err
		end
	end).

find(Ip) ->
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get_index_eq(C, ?BUCKET, {binary_index, "ip"}, Ip) of
			{ok, #index_results_v1{keys = Keys}} ->
				RealKeys = lists:filter(fun(K) ->
					case riakc_pb_socket:get(C, ?BUCKET, K) of
						{ok, RObj} ->
							case merge(riakc_obj:get_values(RObj)) of
								Ip -> true;
								_ -> false
							end;
						_ -> false
					end
				end, Keys),
				{ok, RealKeys};
			Err ->
				Err
		end
	end).

