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
                    Peer = iolist_to_binary(io_lib:format("~B.~B.~B.~B", tuple_to_list(PeerIp))),
                    Meta = jsxd:thread([
                        {set, [<<"hypervisor">>], Peer},
                        {set, [<<"status">>], StatusBin}
                        ], []),
                    %lager:info("~p is now ~p", [IpBin, StatusBin]),
                    ok = db_host_meta:put(IpBin, Meta),
                    Req2 = cowboy_req:reply(200, [], ["ok\n"], Req),
                    {ok, Req2, none};
                false ->
                    lager:info("denying update for ~p from ~p", [IpBin, PeerIp]),
                    Req2 = cowboy_req:reply(403, [], ["access denied\n"], Req),
                    {ok, Req2, none}
            end
    end.
