%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(http_sessupd_handler).
-behaviour(cowboy_handler).

-export([init/2]).

init(Req, _Options) ->
    Method = cowboy_req:method(Req),
    {PeerIp, _PeerPort} = cowboy_req:peer(Req),
    case Method of
        <<"PUT">> ->
            IpBin = cowboy_req:binding(ip, Req),
            case http_api:peer_allowed(IpBin, PeerIp) of
                true ->
                    case cowboy_req:binding(user, Req) of
                        undefined ->
                            %lager:info("~p cleared all sessions", [IpBin]),
                            ok = db_host_meta:put(IpBin, [{<<"sessions">>, []}]),
                            {ok,_} = db_user_status:clear(IpBin),
                            Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
                            {ok, Req2, none};
                        UserBin ->
                            %lager:info("~p register ONLY session for ~p", [IpBin, UserBin]),
                            Meta = jsxd:thread([
                                {set, [<<"sessions">>, 0, <<"user">>], UserBin},
                                {set, [<<"sessions">>, 0, <<"type">>], cowboy_req:binding(type, Req)},
                                {set, [<<"sessions">>, 0, <<"start">>], binary_to_integer(cowboy_req:binding(time, Req))}
                                ], []),
                            ok = db_host_meta:put(IpBin, Meta),

                            {ok,_} = db_user_status:clear(IpBin),
                            ok = db_user_status:put(UserBin, IpBin),
                            Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
                            {ok, Req2, none}
                    end;
                false ->
                    lager:info("denying session update for ~p from ~p", [IpBin, PeerIp]),
                    Req2 = cowboy_req:reply(403, [], ["access denied\n"], Req),
                    {ok, Req2, none}
            end;
        <<"POST">> ->
            IpBin = cowboy_req:binding(ip, Req),
            case http_api:peer_allowed(IpBin, PeerIp) of
                true ->
                    UserBin = cowboy_req:binding(user, Req),
                    %lager:info("~p register session for ~p", [IpBin, UserBin]),
                    ok = db_user_status:put(UserBin, IpBin),
                    Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
                    {ok, Req2, none};
                false ->
                    lager:info("denying session update for ~p from ~p", [IpBin, PeerIp]),
                    Req2 = cowboy_req:reply(403, [], ["access denied\n"], Req),
                    {ok, Req2, none}
            end
    end.
