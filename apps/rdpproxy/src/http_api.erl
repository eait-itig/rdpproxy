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

-include_lib("kernel/include/inet.hrl").

start() ->
    Port = rdpproxy:config([http_api, port], 8080),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/api/host/:ip", http_host_handler, []},
            {"/api/host_count", http_host_handler, []},

            {"/", cowboy_static, {priv_file, rdpproxy, [<<"webroot/index.html">>],
                [{mimetypes, cow_mimetypes, all}]
            }},
            {"/[...]", cowboy_static,
                {priv_dir, rdpproxy, [<<"webroot">>], [
                    {mimetypes, cow_mimetypes, all}
            ]}}
        ]}
    ]),
    cowboy:start_clear(http, [{port, Port}],
        #{env => #{dispatch => Dispatch}}).

rev_lookup(Ip) ->
    case inet_res:gethostbyaddr(Ip) of
        {ok, #hostent{h_name = Name}} when is_list(Name) ->
            case inet_res:gethostbyname(Name) of
                {ok, #hostent{h_addr_list = Addrs}} ->
                    case lists:member(Ip, Addrs) of
                        true -> {ok, Name};
                        false -> {error, reverse_not_match}
                    end;
                _ -> {error, reverse_not_found}
            end;
        E -> {error, E}
    end.

is_rfc1918({A,B,_C,_D}) ->
    (A =:= 10) orelse
        ((A =:= 192) andalso (B =:= 168)) orelse
        ((A =:= 172) andalso (B >= 16) andalso (B =< 31)).

same_slash16({A,B,_C,_D}, {A1,B1,_C1,_D1}) ->
    (A =:= A1) andalso (B =:= B1).

peer_allowed(TargetIpStr, AgentIp) ->
    TargetIp = list_to_tuple([list_to_integer(X) || X <-
        string:tokens(binary_to_list(TargetIpStr), ".")]),
    case rev_lookup(AgentIp) of
        {ok, AgentName} ->
            Suffix = rdpproxy:config([http_api, agent_dns_suffix]),
            case lists:suffix(Suffix, AgentName) of
                true ->
                    DoDnsMatch = rdpproxy:config([http_api,
                        check_agent_dns_matches_host], false),
                    case DoDnsMatch of
                        true ->
                            [Prefix | _] = string:tokens(AgentName, "."),
                            case rev_lookup(TargetIp) of
                                {ok, TargetName} ->
                                    lists:prefix(Prefix, TargetName) andalso
                                        is_rfc1918(AgentIp) andalso
                                        same_slash16(TargetIp, AgentIp);
                                _ -> false
                            end;
                        false ->
                            is_rfc1918(AgentIp) andalso
                                same_slash16(TargetIp, AgentIp)
                    end;
                false -> false
            end;
        _ -> false
    end.
