#!/usr/bin/env escript17
%% -*- erlang -*-
%%! -env ERL_LIBS /opt/rdpproxy/lib

sessions([]) ->
	["none"];
sessions(L) ->
	lists:map(fun(S) ->
		User = proplists:get_value(<<"user">>, S),
		Start = proplists:get_value(<<"start_str">>, S, <<"incomplete">>),
		io_lib:format("~s (~s)", [User, Start])
	end, L).

main([Query]) ->
	[ok = application:start(X) || X <- [poolboy, protobuffs, riak_pb, riakc]],
	poolboy:start_link([{name,{local,riakc_pool}}, {worker_module,riakc_pool}, {size,1}, {max_overflow,2}], ["172.23.84.1",8087]),
	List = case list_to_binary(Query) of
		<<"available">> ->
			{ok, Metas} = db_host_meta:find(status, <<"available">>),
			lists:sort(fun({IpA,A}, {IpB,B}) ->
				RoleA = proplists:get_value(<<"role">>, A),
				RoleB = proplists:get_value(<<"role">>, B),
				ImageA = proplists:get_value(<<"image">>, A, <<>>),
				ImageB = proplists:get_value(<<"image">>, B, <<>>),
				IsLabA = (binary:longest_common_prefix([ImageA, <<"lab">>]) =/= 0),
				IsLabB = (binary:longest_common_prefix([ImageB, <<"lab">>]) =/= 0),
				SessionsA = proplists:get_value(<<"sessions">>, A),
				SessionsB = proplists:get_value(<<"sessions">>, B),
				UpdatedA = proplists:get_value(<<"updated">>, A),
				UpdatedB = proplists:get_value(<<"updated">>, B),
				if
					(RoleA =:= <<"vlab">>) and (not (RoleB =:= <<"vlab">>)) -> true;
					(RoleB =:= <<"vlab">>) and (not (RoleA =:= <<"vlab">>)) -> false;
					IsLabA and (not IsLabB) -> true;
					IsLabB and (not IsLabA) -> false;
					(ImageA > ImageB) -> true;
					(ImageA < ImageB) -> false;
					(length(SessionsA) < length(SessionsB)) -> true;
					(length(SessionsA) > length(SessionsB)) -> false;
					(UpdatedA > UpdatedB) -> true;
					(UpdatedA < UpdatedB) -> false;
					true -> (IpA =< IpB)
				end
			end, Metas);
		<<"busy">> ->
			{ok, Metas} = db_host_meta:find(status, <<"busy">>),
			lists:sort(fun({IpA,A}, {IpB,B}) ->
				RoleA = proplists:get_value(<<"role">>, A),
				RoleB = proplists:get_value(<<"role">>, B),
				if
                                        (RoleA =:= <<"vlab">>) and (not (RoleB =:= <<"vlab">>)) -> true;
                                        (RoleB =:= <<"vlab">>) and (not (RoleA =:= <<"vlab">>)) -> false;
                                        true -> (IpA =< IpB)
				end
			end, Metas);
		<<"incomplete">> ->
			{ok, Metas} = db_host_meta:find(status, <<"busy">>),
			Incomplete = lists:filter(fun({_Ip, D}) ->
				Sessions = proplists:get_value(<<"sessions">>, D),
				case length(Sessions) of
					0 -> true;
					1 ->
						S = lists:nth(1, Sessions),
						case proplists:get_value(<<"start_str">>, S) of
							undefined -> true;
							_ -> false
						end;
					_ -> false
				end
			end, Metas),
			lists:sort(fun({IpA,_}, {IpB,_}) -> (IpA =< IpB) end, Incomplete);
		<<"dead">> ->
			{ok, Metas} = db_host_meta:find(status, <<"dead">>),
			lists:sort(fun({IpA,_}, {IpB,_}) -> (IpA =< IpB) end, Metas);
		_ ->
			{ok, Metas} = db_host_meta:find(user, binary:list_to_bin(Query)),
			Metas
	end,
	io:format("~-20s~-10s~-12s~-20s~-10s\n", [<<"host">>,<<"role">>,<<"status">>,<<"image">>,<<"sessions">>]),
	lists:foreach(fun({Ip, D}) ->
		Sessions = sessions(proplists:get_value(<<"sessions">>, D, [])),
		io:format("~-20s~-10s~-12s~-20s~s\n", [Ip, proplists:get_value(<<"role">>, D), proplists:get_value(<<"status">>, D), proplists:get_value(<<"image">>, D), string:join(Sessions, ",")])
	end, List),
	io:format("~B hosts found\n", [length(List)]);
main(_) ->
	io:format("usage: rdphosts.es [available|busy|dead|<username>]\n").
