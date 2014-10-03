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
    case Method of
        <<"PUT">> ->
            IpBin = cowboy_req:binding(ip, Req),
            ok = db_user_status:clear(IpBin),
            Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
            {ok, Req2, none};
        <<"POST">> ->
        	IpBin = cowboy_req:binding(ip, Req),
        	UserBin = cowboy_req:binding(user, Req),
        	ok = db_user_status:put(UserBin, IpBin),
            Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
            {ok, Req2, none}
    end.
