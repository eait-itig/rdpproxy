%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>
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

-module(conn_ra).

-include_lib("rdp_proto/include/rdpp.hrl").

-export([start/0]).
-export([register_conn/2, tick/0]).
-export([get_user/1, get_all_open/0]).
-export([annotate/2, auth_attempt/2]).
-export([version/0, which_module/1]).

version() -> 2.
which_module(1) -> conn_ra_v1;
which_module(2) -> conn_ra_v2.

start() ->
    Config = application:get_env(rdpproxy, ra, []),
    Nodes = proplists:get_value(nodes, Config, [node() | nodes()]),
    Servers = [{?MODULE, N} || N <- Nodes],
    ra:start_or_restart_cluster(?MODULE_STRING, {module, ?MODULE, #{}}, Servers).

tick() ->
    Time = erlang:system_time(second),
    case ra:process_command(conn_ra, {tick, Time}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

register_conn(Peer = {_Ip, _Port}, Session = #{}) ->
    Now = erlang:system_time(second),
    Id = session_ra:gen_key(),
    Session1 = Session#{password => snip},
    case ra:process_command(conn_ra, {register, Id, self(), Now, Peer, Session1}) of
        {ok, {error, duplicate_id}, _Leader} -> register_conn(Peer, Session1);
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get_user(User) ->
    case ra:process_command(conn_ra, {get_user, User}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get_all_open() ->
    case ra:process_command(conn_ra, get_all_open) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

annotate(SessIdOrPid, Data) ->
    prometheus_counter:inc(rdp_connection_annotations_total),
    Now = erlang:system_time(second),
    case ra:process_command(conn_ra, {annotate, Now, SessIdOrPid, Data}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

auth_attempt(SessIdOrPid, Data) ->
    Now = erlang:system_time(second),
    case ra:process_command(conn_ra, {annotate, Now, SessIdOrPid,
                                      #{auth_attempts => [Data]}}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.
