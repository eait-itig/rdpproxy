%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(http_api).
-export([start/0, peer_allowed/2]).

start() ->
    Port = rdpproxy:config([http_api, port], 8080),
    Dispatch = cowboy_router:compile([
        {'_', [
            % legacy endpoints
            {"/api/host/:ip", http_host_handler, []},
            {"/api/host_count", http_host_handler, []},

            {"/[...]", cowboy_static,
                {priv_dir, rdpproxy, [<<"webroot">>], [
                    {mimetypes, cow_mimetypes, all}
            ]}}
        ]}
    ]),
    cowboy:start_http(http, 20, [{port, Port}],
        [{env, [{dispatch, Dispatch}]}]).

peer_allowed(Ip, PeerIp) ->
    {A,B,_C,_D} = PeerIp,
    [A1,B1,_C1,_D1] = [list_to_integer(X) || X <- string:tokens(binary_to_list(Ip), ".")],
    (A =:= 10) andalso (A =:= A1) andalso (B =:= B1).
