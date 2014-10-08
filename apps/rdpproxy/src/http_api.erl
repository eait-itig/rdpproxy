%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(http_api).
-export([start/0, peer_allowed/2]).

start() ->
    Port = rdpproxy:config([http_api, port], 8080),
    Dispatch = cowboy_router:compile([
        {'_', [
            % legacy endpoints
            {"/status_update/:ip/:status", http_statupd_handler, []},
            {"/session_update/:ip", http_sessupd_handler, []},
            {"/session_update/:ip/:type/:user/:time", http_sessupd_handler, []},
            {"/api/host/:ip", http_host_handler, []},

            {"/[...]", cowboy_static,
                {priv_dir, rdpproxy, [<<"webroot">>], [
                    {mimetypes, cow_mimetypes, all}
            ]}}
        ]}
    ]),
    cowboy:start_http(http, 20, [{port, Port}],
        [{env, [{dispatch, Dispatch}]}]).

peer_allowed(Ip, PeerIp) ->
    {A,B,C,D} = PeerIp,
    [A1,B1,C1,D1] = [list_to_integer(X) || X <- string:tokens(binary_to_list(Ip), ".")],
    (A =:= 10) andalso (A =:= A1) andalso (B =:= B1).
