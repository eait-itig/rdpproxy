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

-module(admin_cli).

-include("session.hrl").
-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/tsud.hrl").

-export([
    help/1,
    alloc_user/1,
    host_create/1,
    host_get/1,
    host_list/1,
    host_enable/1,
    host_disable/1,
    host_help/1,
    conn_help/1,
    conn_list/1,
    conn_user/1
    ]).

help([]) ->
    io:format("usage: rdpproxy-admin <cmd> <subcmd> [args]\n"
              "\n"
              "HOST POOL COMMANDS\n"
              "       rdpproxy-admin host list\n"
              "                      host get <ip>\n"
              "                      host create <ip> <hostname> <port>\n"
              "                      host enable <ip>\n"
              "                      host disable <ip>\n"
              "                      alloc user <user>\n"
              "\n"
              "CONNECTION COMMANDS\n"
              "       rdpproxy-admin conn list\n"
              "                      conn user [-v] <_|user>\n"
              "\n").

host_help(_) -> help([]).

conn_help(_) -> help([]).

alloc_user([User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    {ok, Prefs} = pool_ra:get_prefs(UserBin),
    lists:foreach(fun (Ip) ->
        io:format("~s\n", [Ip])
    end, Prefs).

host_create([Ip, Hostname, Port]) ->
    IpBin = unicode:characters_to_binary(Ip, latin1),
    HostnameBin = unicode:characters_to_binary(Hostname, latin1),
    PortNum = list_to_integer(Port),
    Ret = pool_ra:create(IpBin, HostnameBin, PortNum),
    io:format("~p\n", [Ret]).

host_enable([Ip]) ->
    IpBin = unicode:characters_to_binary(Ip, latin1),
    Ret = pool_ra:enable(IpBin),
    io:format("~p\n", [Ret]).

host_disable([Ip]) ->
    IpBin = unicode:characters_to_binary(Ip, latin1),
    Ret = pool_ra:disable(IpBin),
    io:format("~p\n", [Ret]).

host_get([Ip]) ->
    IpBin = unicode:characters_to_binary(Ip, latin1),
    case pool_ra:get_host(IpBin) of
        {ok, Host} ->
            #{hostname := Hostname, enabled := Ena, image := Img,
              role := Role, last_report := LastRep,
              report_state := {RepState, RepChanged}} = Host,
            #{error_history := EHist, alloc_history := AHist,
              session_history := SHist} = Host,
            LastRepTxt = case LastRep of
                none -> "-";
                _ ->
                    case Host of
                        #{hypervisor := HV} ->
                            io_lib:format("~s (from ~s)", [
                                format_reltime(LastRep), HV]);
                        _ ->
                            format_reltime(LastRep)
                    end
            end,
            RepStateTxt = io_lib:format("~w (~s)",
                [RepState, format_reltime(RepChanged)]),
            io:format("IP            ~s\n", [Ip]),
            io:format("HOSTNAME      ~s\n", [Hostname]),
            io:format("ENABLED       ~p\n", [Ena]),
            io:format("IMAGE         ~s\n", [Img]),
            io:format("ROLE          ~s\n", [Role]),
            io:format("LAST REPORT   ~s\n", [LastRepTxt]),
            io:format("REPORT STATE  ~s\n", [RepStateTxt]),
            io:format("\nRECENT USERS\n"),
            lists:foreach(fun (#{time := AT, user := U}) ->
                io:format(" * ~s (~s)\n", [U, format_reltime(AT)])
            end, queue:to_list(AHist)),
            io:format("\nRECENT ERRORS\n"),
            lists:foreach(fun (#{time := ET, error := Err}) ->
                io:format(" * ~s:\n", [format_reltime(ET)]),
                io:format("    ~p\n", [Err])
            end, queue:to_list(EHist)),
            io:format("\nREPORTED SESSIONS\n"),
            lists:foreach(fun (#{time := ST, user := U, type := T}) ->
                io:format(" * ~s: ~s (~s)\n", [format_reltime(ST), U, T])
            end, queue:to_list(SHist));
        Err ->
            io:format("~p\n", [Err])
    end.

host_list([]) ->
    {ok, Hosts} = pool_ra:get_all_hosts(),
    Fmt = "~16.. s  ~12.. s  ~8.. s  ~26.. s  ~26.. s  ~12.. s  ~8.. s  "
        "~18.. s  ~15.. s\n",
    io:format(Fmt, ["IP", "HOST", "ENABLED", "LASTERR", "LASTUSER", "IMAGE",
        "ROLE", "REPSTATE", "REPORT"]),
    lists:foreach(fun (Host) ->
        #{ip := Ip, hostname := Hostname, enabled := Ena, image := Img,
          role := Role, last_report := LastRep,
          report_state := {RepState, RepChanged}} = Host,
        #{error_history := EHist, alloc_history := AHist} = Host,
        LastErr = case queue:out_r(EHist) of
            {{value, #{time := ET, error := Err}}, _} ->
                iolist_to_binary([
                    io_lib:format("~10w", [Err]),
                    " (", format_reltime(ET), ")"]);
            _ -> "-"
        end,
        LastUser = case queue:out_r(AHist) of
            {{value, #{time := AT, user := U}}, _} ->
                iolist_to_binary([
                    U, " (", format_reltime(AT), ")"]);
            _ -> "-"
        end,
        LastRepTxt = case LastRep of
            none -> "-";
            _ -> format_reltime(LastRep)
        end,
        RepStateTxt = io_lib:format("~w (~s)",
            [RepState, format_reltime(RepChanged)]),
        Fields = [
            Ip,
            Hostname,
            if Ena -> "true"; not Ena -> "false" end,
            LastErr,
            LastUser,
            Img,
            Role,
            RepStateTxt,
            LastRepTxt
        ],
        io:format(Fmt, Fields)
    end, Hosts).

conn_list([]) ->
    {ok, Conns} = conn_ra:get_all_open(),
    Fmt = "~12.. s  ~24.. s  ~10.. s  ~14.. s  ~10.. s  ~15.. s  ~8.. s  ~14.. s  "
        "~11.. s  ~9.. s\n",
    io:format(Fmt, ["ID", "PEER", "NODE", "STARTED", "USER", "BACKEND", "PROTVER",
        "REMHOST", "RES", "RECONN"]),
    ConnsSorted = lists:sort(fun (CA, CB) ->
        #{started := StartedA, id := IdA} = CA,
        #{started := StartedB, id := IdB} = CB,
        if
            (StartedA < StartedB) -> true;
            (StartedA > StartedB) -> false;
            (IdA < IdB) -> true;
            (IdA > IdB) -> false
        end
    end, Conns),
    lists:foreach(fun (Conn) ->
        #{id := Id, started := Started, peer := {Ip, Port}, frontend_pid := Pid,
          session := #session{user = U, host = Backend}} = Conn,
        BackendText = case Conn of
            #{ui_fsm := _} when (Backend =/= undefined) -> [Backend, "*"];
            _ when (Backend =:= undefined) -> "";
            _ -> Backend
        end,
        Peer = io_lib:format("~15.. s :~B", [inet:ntoa(Ip), Port]),
        [_, Node] = binary:split(atom_to_binary(node(Pid), latin1), [<<"@">>]),
        case Conn of
            #{tsuds := Tsuds} ->
                TsudCore = lists:keyfind(tsud_core, 1, Tsuds),
                ProtVer = io_lib:format("~B.~B", TsudCore#tsud_core.version),
                [Client|_] = binary:split(unicode:characters_to_binary(
                    TsudCore#tsud_core.client_name, {utf16, little}, utf8), [<<0>>]),
                #tsud_core{width = W, height = H} = TsudCore,
                Res = case lists:keyfind(tsud_monitor, 1, Tsuds) of
                    #tsud_monitor{monitors = Ms} ->
                        io_lib:format("~Bx~B+~B", [W, H, length(Ms)]);
                    _ ->
                        io_lib:format("~Bx~B", [W, H])
                end,
                TsudCluster = lists:keyfind(tsud_cluster, 1, Tsuds),
                TsInfo = maps:get(ts_info, Conn, #ts_info{}),
                case TsInfo#ts_info.reconnect_cookie of
                    <<>> ->
                        Reconn = "no";
                    undefined ->
                        Reconn = "no";
                    _ when (TsudCluster#tsud_cluster.sessionid =:= none) ->
                        Reconn = "yes";
                    _ ->
                        Reconn = "yes w/sid"
                end;
            _ ->
                ProtVer = "",
                Client = "",
                Res = "",
                Reconn = ""
        end,
        Fields = [
            Id,
            Peer,
            Node,
            format_reltime(Started),
            U,
            BackendText,
            ProtVer,
            Client,
            Res,
            Reconn
        ],
        io:format(Fmt, Fields)
    end, ConnsSorted),
    io:format("count: ~B\n", [length(Conns)]).

conn_user(["-v", User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    {ok, Conns} = conn_ra:get_user(UserBin),
    Fmt = "~12.. s  ~25.. s  ~14.. s  ~14.. s  ~15.. s  ~8.. s  ~10.. s  "
        "~10.. s  ~9.. s\n",
    lists:foreach(fun (Conn) ->
        #{id := Id, started := Started, peer := {Ip, Port}, session := #session{user = U, host = Backend}} = Conn,
        Peer = io_lib:format("~15.. s :~B", [inet:ntoa(Ip), Port]),
        case Conn of
            #{tsuds := Tsuds} ->
                TsudCore = lists:keyfind(tsud_core, 1, Tsuds),
                ProtVer = io_lib:format("~B.~B", TsudCore#tsud_core.version),
                [RemHost|_] = binary:split(unicode:characters_to_binary(
                    TsudCore#tsud_core.client_name, {utf16, little}, utf8), [<<0>>]),
                #tsud_core{width = W, height = H} = TsudCore,
                Res = io_lib:format("~Bx~B", [W, H]),
                TsudCluster = lists:keyfind(tsud_cluster, 1, Tsuds),
                TsInfo = maps:get(ts_info, Conn, #ts_info{}),
                case TsInfo#ts_info.reconnect_cookie of
                    <<>> ->
                        Reconn = "no";
                    undefined ->
                        Reconn = "no";
                    _ when (TsudCluster#tsud_cluster.sessionid =:= none) ->
                        Reconn = "yes";
                    _ ->
                        Reconn = "yes w/sid"
                end;
            _ ->
                Tsuds = [],
                ProtVer = "",
                RemHost = "",
                Res = "",
                Reconn = ""
        end,
        Duration = case Conn of
            #{stopped := Stopped} -> format_deltatime(Stopped - Started, false);
            _ -> ""
        end,
        Fields = [
            Id,
            Peer,
            format_reltime(Started),
            Duration,
            if (Backend =:= undefined) -> ""; true -> Backend end,
            ProtVer,
            RemHost,
            Res,
            Reconn
        ],
        io:format(Fmt, ["ID", "PEER", "STARTED", "DURATION", "BACKEND",
            "PROTVER", "REMHOST", "RES", "RECONN"]),
        io:format(Fmt, Fields),
        io:format("  TSUDS: \n"),
        lists:foreach(fun (Tsud) ->
            io:format("    * ~s\n", [tsud:pretty_print(Tsud)])
        end, Tsuds),
        case Conn of
            #{ts_info := TsInfoV} ->
                io:format("  TS_INFO: ~s\n", [rdpp:pretty_print(TsInfoV)]);
            _ -> ok
        end
    end, Conns);

conn_user([User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    {ok, Conns} = conn_ra:get_user(UserBin),
    Fmt = "~12.. s  ~15.. s  ~14.. s  ~24.. s  ~14.. s  ~14.. s  ~10.. s  ~15.. s  "
        "~8.. s  ~14.. s  ~11.. s  ~9.. s\n",
    io:format(Fmt, ["ID", "PID", "NODE", "PEER", "STARTED", "DURATION", "USER",
        "BACKEND", "PROTVER", "REMHOST", "RES", "RECONN"]),
    lists:foreach(fun (Conn) ->
        #{id := Id, frontend_pid := Pid, started := Started,
          peer := {Ip, Port}, session := #session{user = U, host = Backend}} = Conn,
        Peer = io_lib:format("~15.. s :~B", [inet:ntoa(Ip), Port]),
        BackendText = case Conn of
            #{ui_fsm := _} when (Backend =/= undefined) -> [Backend, "*"];
            _ when (Backend =:= undefined) -> "";
            _ -> Backend
        end,
        [_, Node] = binary:split(atom_to_binary(node(Pid), latin1), [<<"@">>]),
        case Conn of
            #{tsuds := Tsuds} ->
                TsudCore = lists:keyfind(tsud_core, 1, Tsuds),
                ProtVer = io_lib:format("~B.~B", TsudCore#tsud_core.version),
                [RemHost|_] = binary:split(unicode:characters_to_binary(
                    TsudCore#tsud_core.client_name, {utf16, little}, utf8), [<<0>>]),
                #tsud_core{width = W, height = H} = TsudCore,
                Res = case lists:keyfind(tsud_monitor, 1, Tsuds) of
                    #tsud_monitor{monitors = Ms} ->
                        io_lib:format("~Bx~B+~B", [W, H, length(Ms)]);
                    _ ->
                        io_lib:format("~Bx~B", [W, H])
                end,
                TsudCluster = lists:keyfind(tsud_cluster, 1, Tsuds),
                TsInfo = maps:get(ts_info, Conn, #ts_info{}),
                case TsInfo#ts_info.reconnect_cookie of
                    <<>> ->
                        Reconn = "no";
                    undefined ->
                        Reconn = "no";
                    _ when (TsudCluster#tsud_cluster.sessionid =:= none) ->
                        Reconn = "yes";
                    _ ->
                        Reconn = "yes w/sid"
                end;
            _ ->
                ProtVer = "",
                RemHost = "",
                Res = "",
                Reconn = ""
        end,
        Duration = case Conn of
            #{stopped := Stopped} -> format_deltatime(Stopped - Started, false);
            _ -> ""
        end,
        Fields = [
            Id,
            io_lib:format("~w", [Pid]),
            Node,
            Peer,
            format_reltime(Started),
            Duration,
            U,
            BackendText,
            ProtVer,
            RemHost,
            Res,
            Reconn
        ],
        io:format(Fmt, Fields)
    end, Conns).

format_reltime(Time) -> format_reltime(Time, true).
format_reltime(Time, Flavour) ->
    Now = erlang:system_time(second),
    Delta = Now - Time,
    format_deltatime(Delta, Flavour).

format_deltatime(SDelta, Flavour) ->
    Delta = abs(SDelta),
    Secs = Delta rem 60,
    Mins = (Delta div 60) rem 60,
    Hrs = ((Delta div 60) div 60) rem 24,
    Days = ((Delta div 60) div 60) div 24,
    iolist_to_binary([
    if
        (SDelta < 0) and Flavour -> ["in "];
        true -> []
    end,
    if
        (Days > 0) -> [integer_to_list(Days), "d "];
        true -> []
    end,
    if
        (Hrs > 0) -> [integer_to_list(Hrs), "hr "];
        true -> []
    end,
    if
        (Mins > 0) and (Days == 0) -> [integer_to_list(Mins), "m "];
        true -> []
    end,
    if
        (Hrs == 0) and (Days == 0) -> [integer_to_list(Secs), "s"];
        true -> []
    end,
    if
        (SDelta > 0) and Flavour -> [" ago"];
        true -> []
    end
    ]).
