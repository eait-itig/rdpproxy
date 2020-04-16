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
-behaviour(ra_machine).

-include_lib("rdp_proto/include/rdpp.hrl").

-export([init/1, apply/3, state_enter/2]).
-export([start/0]).
-export([register_conn/2, tick/0]).
-export([get_user/1, get_all_open/0]).
-export([annotate/2]).

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
    Now = erlang:system_time(second),
    case ra:process_command(conn_ra, {annotate, Now, SessIdOrPid, Data}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

-define(PAST_CONN_LIMIT, 32).
-define(USER_PAST_CONN_LIMIT, 16).

-type username() :: binary().
-type conn_id() :: binary().
-type conn() :: #{
    id => conn_id(),
    frontend_pid => pid(),
    started => integer(),
    stopped => integer(),
    peer => {inet:ip_address(), integer()},
    session => session_ra:handle_state_nopw(),
    tsuds => [term()],
    ts_info => #ts_info{},
    on_user => boolean()
    }.

-record(?MODULE, {
    users = #{} :: #{username() => queue:queue(conn_id())},
    watches = #{} :: #{pid() => conn_id()},
    conns = #{} :: #{conn_id() => conn()},
    last_time = 0 :: integer()
    }).

init(_Config) ->
    #?MODULE{}.

apply(#{index := Idx}, {tick, T}, S0 = #?MODULE{}) ->
    S1 = S0#?MODULE{last_time = T},
    {S1, ok, [{release_cursor, Idx, S1}]};

apply(_Meta, {get_user, User}, S0 = #?MODULE{conns = C0, users = U0}) ->
    UL0 = case U0 of
        #{User := Q} -> queue:to_list(Q);
        _ -> []
    end,
    UL1 = lists:map(fun(Id) ->
        #{Id := Conn} = C0,
        Conn
    end, UL0),
    {S0, {ok, UL1}, []};

apply(_Meta, get_all_open, S0 = #?MODULE{conns = C0, watches = W0}) ->
    WL0 = maps:values(W0),
    WL1 = lists:foldl(fun(Id, Acc) ->
        case C0 of
            #{Id := Conn} -> [Conn | Acc];
            _ -> Acc
        end
    end, [], WL0),
    {S0, {ok, WL1}, []};

apply(_Meta, {register, Id, Pid, T, Peer, Session},
        S0 = #?MODULE{conns = C0, users = U0, watches = W0}) ->
    case {C0, W0} of
        {#{Id := _}, _} ->
            {S0, {error, duplicate_id}, []};
        {_, #{Pid := _}} ->
            {S0, {error, duplicate_pid}, []};
        _ ->
            Conn = #{
                id => Id,
                frontend_pid => Pid,
                started => T,
                updated => T,
                peer => Peer,
                session => Session,
                on_user => true
            },
            C1 = C0#{Id => Conn},
            #{user := User} = Session,
            UQ0 = case U0 of
                #{User := Q} -> Q;
                _ -> queue:new()
            end,
            UQ1 = queue:in(Id, UQ0),
            Limit = case User of
                <<"_">> -> ?PAST_CONN_LIMIT;
                _ -> ?USER_PAST_CONN_LIMIT
            end,
            {UQ2, C2} = case queue:len(UQ1) of
                N when (N > Limit) ->
                    {{value, OldId}, QQ} = queue:out(UQ1),
                    case C1 of
                        #{OldId := #{stopped := _}} ->
                            {QQ, maps:remove(OldId, C1)};
                        #{OldId := OldConn0} ->
                            OldConn1 = OldConn0#{on_user => false},
                            {QQ, C1#{OldId => OldConn1}};
                        _ ->
                            {QQ, C1}
                    end;
                _ ->
                    {UQ1, C1}
            end,
            U1 = U0#{User => UQ2},
            W1 = W0#{Pid => Id},
            S1 = S0#?MODULE{conns = C2, users = U1, watches = W1},
            {S1, {ok, Id}, [{monitor, process, Pid}]}
    end;

apply(_Meta, {annotate, T, IdOrPid, Map}, S0 = #?MODULE{conns = C0, watches = W0}) ->
    Id = if
        is_pid(IdOrPid) ->
            case W0 of
                #{IdOrPid := I} -> I;
                _ -> unknown
            end;
        true -> IdOrPid
    end,
    case C0 of
        #{Id := Conn0} ->
            Conn1 = maps:fold(fun
                (id, _, Acc) -> Acc;
                (frontend_pid, _, Acc) -> Acc;
                (started, _, Acc) -> Acc;
                (updated, _, Acc) -> Acc;
                (peer, _, Acc) -> Acc;
                (on_user, _, Acc) -> Acc;
                (K, V, Acc) -> Acc#{K => V}
            end, Conn0, Map),
            Conn2 = Conn1#{updated => T},
            C1 = C0#{Id => Conn2},
            S1 = S0#?MODULE{conns = C1},
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {down, Pid, noconnection}, S0 = #?MODULE{}) ->
    {S0, ok, [{monitor, node, node(Pid)}]};

apply(_Meta, {down, Pid, _Reason},
        S0 = #?MODULE{watches = W0, conns = C0, last_time = T}) ->
    #{Pid := Id} = W0,
    C1 = case C0 of
        #{Id := #{on_user := false}} ->
            maps:remove(Id, C0);
        #{Id := Conn0} ->
            Conn1 = Conn0#{stopped => T},
            C0#{Id => Conn1};
        _ -> C0
    end,
    W1 = maps:remove(Pid, W0),
    S1 = S0#?MODULE{watches = W1, conns = C1},
    {S1, ok, []};

apply(_Meta, {nodeup, Node}, S0 = #?MODULE{watches = W0}) ->
    Effects = maps:fold(fun
        (Pid, _Id, Acc) when (node(Pid) =:= Node) ->
            [{monitor, process, Pid} | Acc];
        (_Pid, _Id, Acc) -> Acc
    end, [], W0),
    {S0, ok, Effects};

apply(_Meta, {nodedown, _}, S0 = #?MODULE{}) ->
    {S0, ok, []}.

state_enter(leader, #?MODULE{watches = W0}) ->
    maps:fold(fun (Pid, _Id, Acc) ->
        [{monitor, process, Pid} | Acc]
    end, [], W0);
state_enter(_, #?MODULE{}) -> [].
