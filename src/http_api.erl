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
-export([start/0, peer_allowed/2, rev_lookup/1]).

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

mask_ip({A,B,C,D}, Bits) ->
    <<N0:32/big>> = <<A,B,C,D>>,
    N1 = N0 band (bnot ((1 bsl (32 - Bits)) - 1)),
    <<A2,B2,C2,D2>> = <<N1:32/big>>,
    {A2, B2, C2, D2}.

match_rule(_TargetIp, AgentIp, {_, net, Ip, Mask}) ->
    Good = mask_ip(Ip, Mask),
    case mask_ip(AgentIp, Mask) of
        Good -> match;
        _ -> no_match
    end;
match_rule(_TargetIp, AgentIp, {_, dns_suffix, Suffix}) ->
    case rev_lookup(AgentIp) of
        {ok, AgentName} ->
            case lists:suffix(Suffix, AgentName) of
                true -> match;
                _ -> no_match
            end;
        _ -> no_match
    end;
match_rule(_TargetIp, AgentIp, {_, rfc1918, Want}) ->
    case {is_rfc1918(AgentIp), Want} of
        {true, true} -> match;
        {true, false} -> no_match;
        {false, true} -> no_match;
        {false, false} -> match
    end;
match_rule(TargetIp, AgentIp, {_, same_net, Mask}) ->
    Good = mask_ip(TargetIp, Mask),
    case mask_ip(AgentIp, Mask) of
        Good -> match;
        _ -> no_match
    end;
match_rule(TargetIp, AgentIp, {_, same_dns_prefix, CTN, CAN}) ->
    TRev = rev_lookup(TargetIp),
    ARev = rev_lookup(AgentIp),
    case {TRev, ARev} of
        {{ok, TargetName}, {ok, AgentName}} ->
            CT = lists:nth(CTN, string:tokens(TargetName, ".")),
            CA = lists:nth(CAN, string:tokens(AgentName, ".")),
            case lists:prefix(CA, CT) of
                true -> match;
                _ -> no_match
            end;
        _ -> no_match
    end.

process_rules(_TargetIp, _AgentIp, []) -> allow;
process_rules(TargetIp, AgentIp, [Rule | Rest]) ->
    Match = match_rule(TargetIp, AgentIp, Rule),
    case {Match, element(1, Rule)} of
        {match, allow} -> allow;
        {match, deny} -> deny;
        {no_match, require} -> deny;
        _ -> process_rules(TargetIp, AgentIp, Rest)
    end.

peer_allowed(TargetIpStr, AgentIp) ->
    Rules = rdpproxy:config([http_api, access_policy],
        [{allow, net, {127,0,0,0}, 16}]),
    {ok, TargetIp} = inet:parse_address(binary_to_list(TargetIpStr)),
    case process_rules(TargetIp, AgentIp, Rules) of
        allow -> true;
        deny -> false
    end.
