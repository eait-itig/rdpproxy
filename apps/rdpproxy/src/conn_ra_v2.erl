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

-module(conn_ra_v2).
-behaviour(ra_machine).

-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/tsud.hrl").

-export([init/1, apply/3, state_enter/2]).
-export([version/0]).

-export([register_metrics/0]).

-export([conn_to_json/1]).

version() -> 2.

register_metrics() ->
    prometheus_gauge:new([
        {name, rdp_connections_open},
        {help, "Count of RDP connections open"}]),
    prometheus_counter:new([
        {name, rdp_connection_logs_written_total},
        {help, "Count of hourly connection logs written out"}]),
    prometheus_counter:new([
        {name, rdp_connection_records_written_total},
        {help, "Count of hourly connection log records written out"}]),
    prometheus_gauge:new([
        {name, rdp_connection_logs_open},
        {help, "Number of hourly connection logs open and not yet written"}]),
    prometheus_counter:new([
        {name, rdp_connection_annotations_total},
        {help, "Annotation operations processed"}]),
    ok.

-define(PAST_CONN_LIMIT, 32).
-define(USER_PAST_CONN_LIMIT, 16).
-define(LOG_TIME_UNIT_SEC, 3600).

-type auth_attempt() :: #{
    username => binary(),
    status => success | failure,
    stage => atom() | {atom(), term()},
    reason => term(),
    time => integer()
    }.
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
    on_user => boolean(),
    on_hour => boolean(),
    auth_attempts => [auth_attempt()],
    duo_preauth => binary()
    }.

-type hour_num() :: integer().
-type alive_count() :: integer().
-type hour() :: #{
    count => alive_count(),
    conns => [conn_id()]
    }.

-record(?MODULE, {
    users = #{} :: #{username() => queue:queue(conn_id())},
    watches = #{} :: #{pid() => conn_id()},
    conns = #{} :: #{conn_id() => conn()},
    hours = #{} :: #{hour_num() => hour()},
    hourlives = gb_trees:from_orddict([{0, []}]) :: gb_trees:tree(alive_count(), [hour_num()]),
    last_time = 0 :: integer()
    }).

-record(conn_ra, {
    users = #{} :: #{username() => queue:queue(conn_id())},
    watches = #{} :: #{pid() => conn_id()},
    conns = #{} :: #{conn_id() => conn()},
    last_time = 0 :: integer()
    }).

-record(conn_ra_v1, {
    users = #{} :: #{username() => queue:queue(conn_id())},
    watches = #{} :: #{pid() => conn_id()},
    conns = #{} :: #{conn_id() => conn()},
    hours = gb_trees:empty() :: gb_trees:tree(integer(), [conn_id()]),
    last_time = 0 :: integer()
    }).

session_to_json(#{handle := Hdl, user := U, ip := Ip, port := Port}) ->
    J0 = #{
        <<"handle">> => Hdl,
        <<"user">> => U,
        <<"backend">> => #{
            <<"ip">> => Ip,
            <<"port">> => Port
        }
    },
    case session_ra:get_host(Ip) of
        {ok, #{pool := Pool}} ->
            J0#{<<"pool">> => atom_to_binary(Pool, utf8)};
        _ ->
            J0
    end;
session_to_json(#{user := U}) ->
    #{
        <<"user">> => U
    }.

tsuds_to_json(Tsuds) ->
    TsudCore = lists:keyfind(tsud_core, 1, Tsuds),
    [Major, Minor] = TsudCore#tsud_core.version,
    TsudsGiven = [atom_to_binary(element(1, X), utf8) || X <- Tsuds],
    [Hostname|_] = binary:split(unicode:characters_to_binary(
        TsudCore#tsud_core.client_name, {utf16, little}, utf8), [<<0>>]),
    J0 = #{
        <<"given">> => TsudsGiven,
        <<"version">> => iolist_to_binary(io_lib:format("~B.~B", [Major, Minor])),
        <<"build">> => TsudCore#tsud_core.client_build,
        <<"width">> => TsudCore#tsud_core.width,
        <<"height">> => TsudCore#tsud_core.height,
        <<"color">> => #{
            <<"preferred">> => atom_to_binary(TsudCore#tsud_core.color, utf8),
            <<"supported">> => [ atom_to_binary(X, utf8) ||
                X <- TsudCore#tsud_core.colors ]
        },
        <<"capabilities">> => [ atom_to_binary(X, utf8) ||
            X <- TsudCore#tsud_core.capabilities ],
        <<"hostname">> => Hostname
    },
    J1 = case lists:keyfind(tsud_monitor, 1, Tsuds) of
        #tsud_monitor{monitors = Ms} ->
            J0#{
                <<"monitors">> => [
                    #{
                        <<"left">> => Left,
                        <<"top">> => Top,
                        <<"right">> => Right,
                        <<"bottom">> => Bottom,
                        <<"flags">> => [ atom_to_binary(X, utf8) || X <- Fs ]
                    }
                    || #tsud_monitor_def{flags = Fs, left = Left, top = Top,
                        right = Right, bottom = Bottom}
                    <- Ms
                ]
            };
        _ -> J0
    end,
    _J2 = case lists:keyfind(tsud_cluster, 1, Tsuds) of
        #tsud_cluster{sessionid = SessId} ->
            J1#{<<"session_id">> => SessId};
        _ ->
            J1
    end.

ts_info_to_json(TsInfo = #ts_info{}) ->
    #ts_info{domain = D0, username = U0} = TsInfo,
    [U|_] = binary:split(unicode:characters_to_binary(U0, {utf16, little},
        utf8), [<<0>>]),
    [D|_] = binary:split(unicode:characters_to_binary(D0, {utf16, little},
        utf8), [<<0>>]),
    Tz = case TsInfo#ts_info.timezone of
        #ts_timezone{name = TzNameBin} ->
            case unicode:characters_to_binary(TzNameBin, {utf16, little}, utf8) of
                {incomplete, TzName, _} -> TzName;
                WithZero ->
                    [TzName|_] = binary:split(WithZero, [<<0>>]),
                    TzName
            end;
        _ ->
            <<"unknown">>
    end,
    _J0 = #{
        <<"domain">> => D,
        <<"username">> => U,
        <<"flags">> => [ atom_to_binary(X, utf8) || X <- TsInfo#ts_info.flags ],
        <<"compression">> => atom_to_binary(TsInfo#ts_info.compression, utf8),
        <<"reconnect_cookie">> => if
            (byte_size(TsInfo#ts_info.reconnect_cookie) > 0) -> true;
            true -> false
        end,
        <<"timezone">> => Tz,
        <<"client_ip">> => iolist_to_binary(io_lib:format("~w", [
            TsInfo#ts_info.client_address]))
    }.

ts_caps_to_json(TsCaps) ->
    GenCap = lists:keyfind(ts_cap_general, 1, TsCaps),
    #ts_cap_general{os = [OsType, OsSubType], flags = Flags} = GenCap,
    BitmapCap = lists:keyfind(ts_cap_bitmap, 1, TsCaps),
    #ts_cap_bitmap{bpp = Bpp, width = W, height = H} = BitmapCap,
    #{
        <<"os_type">> => atom_to_binary(OsType, utf8),
        <<"os_subtype">> => atom_to_binary(OsSubType, utf8),
        <<"general_flags">> => [ atom_to_binary(X, utf8) || X <- Flags ],
        <<"bitmap_bpp">> => Bpp,
        <<"bitmap_width">> => W,
        <<"bitmap_height">> => H
    }.

conn_to_json(C) ->
    #{id := Id, frontend_pid := Pid, started := Started, stopped := Stopped,
      peer := {PeerIp, PeerPort}, session := Sess} = C,
    [_, Node] = binary:split(atom_to_binary(node(Pid), latin1), [<<"@">>]),
    Duration = Stopped - Started,
    J0 = #{
        <<"id">> => Id,
        <<"pid">> => iolist_to_binary(io_lib:format("~w", [Pid])),
        <<"node">> => Node,
        <<"peer">> => #{
            <<"ip">> => iolist_to_binary(inet:ntoa(PeerIp)),
            <<"port">> => PeerPort
        },
        <<"started">> => iolist_to_binary(
            calendar:system_time_to_rfc3339(Started)),
        <<"stopped">> => iolist_to_binary(
            calendar:system_time_to_rfc3339(Stopped)),
        <<"session">> => session_to_json(Sess),
        <<"duration">> => Duration
    },
    J1 = case C of
        #{tsuds := Tsuds} -> J0#{<<"tsuds">> => tsuds_to_json(Tsuds)};
        _ -> J0
    end,
    J2 = case C of
        #{ts_info := TsInfo} -> J1#{<<"ts_info">> => ts_info_to_json(TsInfo)};
        _ -> J1
    end,
    J3 = case C of
        #{ts_caps := TsCaps} -> J2#{<<"ts_caps">> => ts_caps_to_json(TsCaps)};
        _ -> J2
    end,
    J4 = case C of
        #{duo_preauth := Preauth} -> J3#{<<"duo_preauth">> => Preauth};
        _ -> J3
    end,
    J5 = case C of
        #{auth_attempts := []} -> J4;
        #{auth_attempts := AT = [_|_]} ->
            ATJ = lists:map(fun
                (#{username := U, status := Status, time := T,
                   stage := Stage, reason := Reason}) ->
                    #{<<"username">> => U,
                      <<"status">> => atom_to_binary(Status, utf8),
                      <<"time">> => iolist_to_binary(
                          calendar:system_time_to_rfc3339(T)),
                      <<"stage">> => iolist_to_binary(
                          io_lib:format("~p", [Stage])),
                      <<"reason">> => iolist_to_binary(
                          io_lib:format("~p", [Reason]))};
                (#{username := U, status := Status, time := T}) ->
                    #{<<"username">> => U,
                      <<"status">> => atom_to_binary(Status, utf8),
                      <<"time">> => iolist_to_binary(
                          calendar:system_time_to_rfc3339(T))};
                (#{username := U, time := T}) ->
                    #{<<"username">> => U,
                      <<"time">> => iolist_to_binary(
                          calendar:system_time_to_rfc3339(T))};
                (#{username := U}) ->
                    #{<<"username">> => U}
            end, AT),
            J4#{<<"auth_attempts">> => ATJ};
        _ -> J4
    end,
    J6 = case C of
        #{forwarded_creds := FC} -> J5#{<<"forwarded_creds">> => FC};
        _ -> J5
    end,
    J7 = case C of
        #{avg_ping := unknown} -> J6;
        #{avg_ping := N} -> J6#{<<"avg_ping">> => N};
        _ -> J6
    end,
    J8 = case C of
        #{ts_session_id := SessId} -> J7#{<<"backend_session_id">> => SessId};
        _ -> J7
    end,
    J9 = case C of
        #{ts_session_status := BSt} ->
            J8#{
                <<"backend_session_status">> => iolist_to_binary(
                    io_lib:format("~p", [BSt]))
            };
        _ -> J8
    end,
    [jsx:encode(J9), $\n].

evict_hour(Hour, S0 = #?MODULE{hours = H0, hourlives = HL0, conns = C0}) ->
    #{Hour := #{count := 0, conns := ConnKeys}} = H0,
    H1 = maps:remove(Hour, H0),

    ZeroHours0 = gb_trees:get(0, HL0),
    HL1 = gb_trees:update(0, ZeroHours0 -- [Hour], HL0),

    C1 = lists:foldl(fun (Key, Acc) ->
        case Acc of
            #{Key := #{stopped := _, on_user := false}} ->
                maps:remove(Key, Acc);
            #{Key := Conn0} ->
                Acc#{Key => Conn0#{on_hour => false}}
        end
    end, C0, ConnKeys),
    FName = iolist_to_binary(["log/connections.log_",
        calendar:system_time_to_rfc3339(Hour * ?LOG_TIME_UNIT_SEC,
            [{time_designator, $_}])]),
    Json = iolist_to_binary(lists:map(fun (Key) ->
        #{Key := Conn} = C0,
        prometheus_counter:inc(rdp_connection_records_written_total),
        conn_to_json(Conn)
    end, lists:reverse(ConnKeys))),
    lager:debug("writing connection log ~s (~B conns)",
        [FName, length(ConnKeys)]),
    file:write_file(FName, Json),

    prometheus_counter:inc(rdp_connection_logs_written_total),

    S0#?MODULE{hours = H1, hourlives = HL1, conns = C1}.

incr_hourlive(Hour, Incr, S0 = #?MODULE{hours = H0, hourlives = HL0}) ->
    case H0 of
        #{Hour := #{count := HN0} = Hour0} ->
            HN1 = HN0 + Incr,
            true = (HN1 >= 0),
            OldHrs0 = gb_trees:get(HN0, HL0),
            HL1 = gb_trees:update(HN0, OldHrs0 -- [Hour], HL0),
            HL2 = case gb_trees:lookup(HN1, HL1) of
                none ->
                    gb_trees:insert(HN1, [Hour], HL1);
                {value, NewHrs0} ->
                    gb_trees:update(HN1, NewHrs0 ++ [Hour], HL1)
            end,
            H1 = H0#{Hour => Hour0#{count => HN1}},
            S0#?MODULE{hours = H1, hourlives = HL2};
        _ ->
            true = (Incr >= 0),
            HL1 = case gb_trees:lookup(Incr, HL0) of
                none ->
                    gb_trees:insert(Incr, [Hour], HL0);
                {value, NewHrs0} ->
                    gb_trees:update(Incr, NewHrs0 ++ [Hour], HL0)
            end,
            H1 = H0#{Hour => #{count => Incr, conns => []}},
            S0#?MODULE{hours = H1, hourlives = HL1}
    end.

init(_Config) ->
    #?MODULE{}.

apply(_Meta, {machine_version, 0, 2}, S0) ->
    #conn_ra{users = U, watches = W, conns = C0, last_time = LT} = S0,
    C1 = maps:map(fun (_K, Conn0) ->
        Conn0#{on_hour => true}
    end, C0),
    S1 = #?MODULE{users = U, watches = W, conns = C1, last_time = LT},
    S2 = lists:foldl(fun ({Id, Conn}, Acc) ->
        #{started := Started} = Conn,
        Hour = Started div ?LOG_TIME_UNIT_SEC,
        Incr = case Conn of
            #{stopped := _} -> 0;
            _ -> 1
        end,
        Acc1 = incr_hourlive(Hour, Incr, Acc),
        #?MODULE{hours = H0} = Acc1,
        #{Hour := Hour0 = #{conns := HConns0}} = H0,
        H1 = H0#{Hour => Hour0#{conns => [Id | HConns0]}},
        Acc1#?MODULE{hours = H1}
    end, S1, maps:to_list(C0)),
    {S2, ok, []};

apply(_Meta, {machine_version, 1, 2}, S0) ->
    #conn_ra_v1{users = U, watches = W, conns = C0, last_time = LT} = S0,
    C1 = maps:map(fun (_K, Conn0) ->
        Conn0#{on_hour => true}
    end, C0),
    S1 = #?MODULE{users = U, watches = W, conns = C1, last_time = LT},
    S2 = lists:foldl(fun ({Id, Conn}, Acc) ->
        #{started := Started} = Conn,
        Hour = Started div ?LOG_TIME_UNIT_SEC,
        Incr = case Conn of
            #{stopped := _} -> 0;
            _ -> 1
        end,
        Acc1 = incr_hourlive(Hour, Incr, Acc),
        #?MODULE{hours = H0} = Acc1,
        #{Hour := Hour0 = #{conns := HConns0}} = H0,
        H1 = H0#{Hour => Hour0#{conns => [Id | HConns0]}},
        Acc1#?MODULE{hours = H1}
    end, S1, maps:to_list(C0)),
    {S2, ok, []};

apply(#{index := Idx}, {tick, T}, S0 = #?MODULE{hourlives = HL0}) ->
    CurHour = T div ?LOG_TIME_UNIT_SEC,
    S1 = case gb_trees:smallest(HL0) of
        {0, []} -> S0;
        {0, Hours} ->
            FinishedHours = lists:filter(
                fun (Hour) -> CurHour > Hour end, Hours),
            lists:foldl(fun evict_hour/2, S0, FinishedHours)
    end,
    prometheus_gauge:set(rdp_connection_logs_open, maps:size(S1#?MODULE.hours)),
    S2 = S1#?MODULE{last_time = T},
    {S2, ok, [{release_cursor, Idx, S2}]};

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
                on_user => true,
                on_hour => true,
                auth_attempts => []
            },
            Hour = T div ?LOG_TIME_UNIT_SEC,
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
                        #{OldId := #{stopped := _, on_hour := false}} ->
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
            prometheus_gauge:set(rdp_connections_open, maps:size(W1)),
            S1 = incr_hourlive(Hour, 1, S0),
            #?MODULE{hours = H0} = S1,
            #{Hour := Hour0 = #{conns := HConns0}} = H0,
            H1 = H0#{Hour => Hour0#{conns => [Id | HConns0]}},
            S2 = S1#?MODULE{hours = H1, conns = C2, users = U1, watches = W1},
            {S2, {ok, Id}, [{monitor, process, Pid}]}
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
                (auth_attempts, V, Acc) ->
                    #{auth_attempts := Attempts0} = Acc,
                    Acc#{auth_attempts => Attempts0 ++ V};
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
    case W0 of
        #{Pid := Id} ->
            S1 = case C0 of
                #{Id := #{on_user := false, on_hour := false}} ->
                    S0#?MODULE{conns = maps:remove(Id, C0)};
                #{Id := #{stopped := _}} ->
                    S0;
                #{Id := Conn0 = #{started := Started, on_hour := true}} ->
                    Conn1 = Conn0#{stopped => T},
                    C1 = C0#{Id => Conn1},
                    Hour = Started div ?LOG_TIME_UNIT_SEC,
                    incr_hourlive(Hour, -1, S0#?MODULE{conns = C1});
                #{Id := Conn0} ->
                    Conn1 = Conn0#{stopped => T},
                    C1 = C0#{Id => Conn1},
                    S0#?MODULE{conns = C1};
                _ ->
                    S0
            end,
            W1 = maps:remove(Pid, W0),
            prometheus_gauge:set(rdp_connections_open, maps:size(W1)),
            S2 = S1#?MODULE{watches = W1},
            {S2, ok, []};
        _ ->
            lager:error("conn_ra got down msg for non-watched pid: ~p", [Pid]),
            {S0, ok, []}
    end;

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
