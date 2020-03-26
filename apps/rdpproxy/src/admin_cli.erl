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
    host_create/1,
    host_get/1,
    host_list/1,
    host_enable/1,
    host_disable/1,
    conn_list/1,
    conn_user/1
    ]).

help([]) ->
    io:format("usage: rdpproxy-admin <cmd>\n").

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
            #{hostname := Hostname, enabled := Ena, image := Img, role := Role} = Host,
            #{error_history := EHist, alloc_history := AHist} = Host,
            io:format("IP            ~s\n", [Ip]),
            io:format("HOSTNAME      ~s\n", [Hostname]),
            io:format("ENABLED       ~p\n", [Ena]),
            io:format("IMAGE         ~s\n", [Img]),
            io:format("ROLE          ~s\n", [Role]),
            io:format("\nRECENT USERS\n"),
            lists:foreach(fun (#{time := AT, user := U}) ->
                io:format(" * ~s (~s)\n", [U, format_reltime(AT)])
            end, queue:to_list(AHist)),
            io:format("\nRECENT ERRORS\n"),
            lists:foreach(fun (#{time := ET, error := Err}) ->
                io:format(" * ~s:\n", [format_reltime(ET)]),
                io:format("    ~p\n", [Err])
            end, queue:to_list(EHist));
        Err ->
            io:format("~p\n", [Err])
    end.

host_list([]) ->
    {ok, Hosts} = pool_ra:get_all_hosts(),
    Fmt = "~16.. s  ~12.. s  ~8.. s  ~25.. s  ~25.. s  ~12.. s  ~8.. s\n",
    io:format(Fmt, ["IP", "HOST", "ENABLED", "LASTERR", "LASTUSER", "IMAGE", "ROLE"]),
    lists:foreach(fun (Host) ->
        #{ip := Ip, hostname := Hostname, enabled := Ena, image := Img, role := Role} = Host,
        #{error_history := EHist, alloc_history := AHist} = Host,
        LastErr = case queue:out_r(EHist) of
            {{value, #{time := ET, error := Err}}, _} ->
                iolist_to_binary([
                    io_lib:format("~10w", [Err]),
                    " (", format_reltime(ET), ")"]);
            _ -> ""
        end,
        LastUser = case queue:out_r(AHist) of
            {{value, #{time := AT, user := U}}, _} ->
                iolist_to_binary([
                    U, " (", format_reltime(AT), ")"]);
            _ -> ""
        end,
        Fields = [
            Ip,
            Hostname,
            if Ena -> "true"; not Ena -> "false" end,
            LastErr,
            LastUser,
            Img,
            Role
        ],
        io:format(Fmt, Fields)
    end, Hosts).

conn_list([]) ->
    {ok, Conns} = conn_ra:get_all_open(),
    Fmt = "~12.. s  ~20.. s  ~14.. s  ~10.. s  ~12.. s  ~8.. s  ~10.. s  "
        "~10.. s  ~9.. s\n",
    io:format(Fmt, ["ID", "PEER", "STARTED", "USER", "BACKEND", "PROTVER",
        "REMHOST", "RES", "RECONN"]),
    lists:foreach(fun (Conn) ->
        #{id := Id, started := Started, peer := {Ip, Port}, session := #session{user = U, host = Backend}} = Conn,
        Peer = io_lib:format("~s : ~B", [inet:ntoa(Ip), Port]),
        case Conn of
            #{tsuds := Tsuds} ->
                TsudCore = lists:keyfind(tsud_core, 1, Tsuds),
                ProtVer = io_lib:format("~B.~B", TsudCore#tsud_core.version),
                [Client|_] = binary:split(unicode:characters_to_binary(
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
                ProtVer = "",
                Client = "",
                Res = "",
                Reconn = ""
        end,
        Fields = [
            Id,
            Peer,
            format_reltime(Started),
            U,
            if (Backend =:= undefined) -> ""; true -> Backend end,
            ProtVer,
            Client,
            Res,
            Reconn
        ],
        io:format(Fmt, Fields)
    end, Conns).

conn_user(["-v", User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    {ok, Conns} = conn_ra:get_user(UserBin),
    Fmt = "~12.. s  ~20.. s  ~14.. s  ~14.. s  ~12.. s  ~8.. s  ~10.. s  "
        "~10.. s  ~9.. s\n",
    lists:foreach(fun (Conn) ->
        #{id := Id, started := Started, peer := {Ip, Port}, session := #session{user = U, host = Backend}} = Conn,
        Peer = io_lib:format("~s : ~B", [inet:ntoa(Ip), Port]),
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
    Fmt = "~12.. s  ~12.. s  ~20.. s  ~14.. s  ~14.. s  ~10.. s  ~12.. s  "
        "~8.. s  ~10.. s  ~10.. s  ~9.. s\n",
    io:format(Fmt, ["ID", "PID", "PEER", "STARTED", "DURATION", "USER",
        "BACKEND", "PROTVER", "REMHOST", "RES", "RECONN"]),
    lists:foreach(fun (Conn) ->
        #{id := Id, frontend_pid := Pid, started := Started,
          peer := {Ip, Port}, session := #session{user = U, host = Backend}} = Conn,
        Peer = io_lib:format("~s : ~B", [inet:ntoa(Ip), Port]),
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
            Peer,
            format_reltime(Started),
            Duration,
            U,
            if (Backend =:= undefined) -> ""; true -> Backend end,
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
        (Secs > 0) and (Hrs == 0) and (Days == 0) -> [integer_to_list(Secs), "s "];
        true -> []
    end,
    if
        (SDelta > 0) and Flavour -> [" ago"];
        true -> []
    end
    ]).
