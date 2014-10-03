%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(db_host_status).
-include_lib("riakc/include/riakc.hrl").

-export([get/1, put/2, find/1]).

-define(POOL, riakc_pool).
-define(BUCKET, <<"rdp_host_status">>).

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

get(Ip) ->
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get(C, ?BUCKET, Ip) of
			{ok, RObj} ->
				Status = merge(riakc_obj:get_values(RObj)),
				{ok, Status};
			{error, Reason} ->
				{error, Reason}
		end
	end).

put(Ip, Status) ->
	RObj0 = poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get(C, ?BUCKET, Ip) of
			{ok, R} -> riakc_obj:update_value(R, encode_new_val(Status));
			_ -> riakc_obj:new(?BUCKET, Ip, encode_new_val(Status))
		end
	end),
	MD0 = riakc_obj:get_update_metadata(RObj0),
	MD1 = riakc_obj:set_secondary_index(MD0, [{{binary_index, "status"}, [Status]}]),
	RObj = riakc_obj:update_metadata(RObj0, MD1),
	poolboy:transaction(?POOL, fun(C) ->
		riakc_pb_socket:put(C, RObj, [])
	end).

find(Status) ->
	poolboy:transaction(?POOL, fun(C) ->
		case riakc_pb_socket:get_index_eq(C, ?BUCKET, {binary_index, "status"}, Status) of
			{ok, #index_results_v1{keys = Keys}} ->
				RealKeys = lists:filter(fun(K) ->
					case riakc_pb_socket:get(C, ?BUCKET, K) of
						{ok, RObj} ->
							case merge(riakc_obj:get_values(RObj)) of
								Status -> true;
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

