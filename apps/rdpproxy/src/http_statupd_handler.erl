%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(http_statupd_handler).
-behaviour(cowboy_handler).

-export([init/2]).

init(Req, _Options) ->
    Method = cowboy_req:method(Req),
    {PeerIp, _PeerPort} = cowboy_req:peer(Req),
    case Method of
        B when (B =:= <<"PUT">>) or (B =:= <<"POST">>) ->
            IpBin = cowboy_req:binding(ip, Req),
            case http_api:peer_allowed(IpBin, PeerIp) of
                true ->
                    StatusBin = cowboy_req:binding(status, Req),
                    %lager:info("~p is now ~p", [IpBin, StatusBin]),
                    ok = db_host_status:put(IpBin, StatusBin),
                    Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
                    {ok, Req2, none};
                false ->
                    lager:info("denying update for ~p from ~p", [IpBin, PeerIp]),
                    Req2 = cowboy_req:reply(403, [], ["access denied\n"], Req),
                    {ok, Req2, none}
            end
    end.
