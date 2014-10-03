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
    case Method of
        B when (B =:= <<"PUT">>) or (B =:= <<"POST">>) ->
            IpBin = cowboy_req:binding(ip, Req),
            StatusBin = cowboy_req:binding(status, Req),
            ok = db_host_status:put(IpBin, StatusBin),
            Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
            {ok, Req2, none}
    end.
