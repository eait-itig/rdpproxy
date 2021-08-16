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

-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/tsud.hrl").

-export([
    help/1,
    alloc_host/1,
    alloc_pool/1,
    pool_list/1,
    pool_get/1,
    pool_create/1,
    pool_update/1,
    pool_help/1,
    host_create/1,
    host_get/1,
    host_list/1,
    host_delete/1,
    host_test/1,
    host_update/1,
    host_enable/1,
    host_disable/1,
    host_help/1,
    conn_help/1,
    conn_list/1,
    conn_user/1,
    handle_get/1,
    handle_list/1,
    handle_help/1,
    dump_sessions/1,
    dump_conns/1,
    pool_reprobe/1,
    pool_errors/1
    ]).

-export([print_prefs/1]).

help([]) ->
    io:format("usage: rdpproxy-admin <cmd> <subcmd> [args]\n"
              "\n"
              "POOL COMMANDS\n"
              "       rdpproxy-admin pool list\n"
              "                      pool get <name>\n"
              "                      pool create <name> [k=v]\n"
              "                      pool update <name> <k=v>\n"
              "                      alloc pool <user>\n"
              "\n"
              "HOST COMMANDS\n"
              "       rdpproxy-admin host list\n"
              "                      host list <pool>\n"
              "                      host get <ip|hostname>\n"
              "                      host create <pool> <ip> [k=v]\n"
              "                      host update <ip|hostname> <k=v>\n"
              "                      host enable <ip|hostname>\n"
              "                      host disable <ip|hostname>\n"
              "                      host delete <ip|hostname>\n"
              "                      host test <ip|hostname>\n"
              "                      alloc host <pool> <user>\n"
              "\n"
              "CONNECTION COMMANDS\n"
              "       rdpproxy-admin conn list [-j]\n"
              "                      conn user [-j] <_|user>\n"
              "\n"
              "SESSION HANDLE COMMANDS\n"
              "       rdpproxy-admin handle list\n"
              "                      handle get <hdl>\n"
              "\n").

host_help(_) -> help([]).

conn_help(_) -> help([]).

pool_help(_) -> help([]).

handle_help(_) -> help([]).

handle_get([Hdl]) ->
    Res = session_ra:get_handle(list_to_binary(Hdl)),
    io:format("~p\n", [Res]).

handle_list([]) ->
    Fmt = "~17.. s  ~16.. s  ~16.. s  ~16.. s  ~10.. s  ~20.. s  ~20.. s  ~20.. s  ~20.. s\n",
    io:format(Fmt, ["HANDLE", "USER", "POOL", "IP", "STATE", "START", "MIN", "EXPIRY", "PID"]),
    {ok, Hdls} = session_ra:get_all_handles(),
    HdlsWithHosts = lists:map(fun (HD) ->
        #{ip := Ip} = HD,
        {ok, Host} = session_ra:get_host(Ip),
        HD#{host => Host}
    end, Hdls),
    HdlsSorted = lists:sort(fun (A, B) ->
        #{handle := HdlA, pid := PidA, start := StartA, host := HA} = A,
        #{handle := HdlB, pid := PidB, start := StartB, host := HB} = B,
        #{pool := PoolA} = HA,
        #{pool := PoolB} = HB,
        HasPidA = not (PidA =:= none),
        HasPidB = not (PidB =:= none),
        if
            HasPidA and (not HasPidB) -> true;
            (not HasPidA) and HasPidB -> false;
            PoolA < PoolB -> true;
            PoolA > PoolB -> false;
            StartA < StartB -> true;
            StartA > StartB -> false;
            HdlA < HdlB -> true;
            HdlA > HdlB -> false
        end
    end, HdlsWithHosts),
    lists:foreach(fun (HD) ->
        #{handle := Hdl, user := User, start := Start, min := Min, pid := Pid,
          expiry := Expiry, ip := Ip, state := St, host := H} = HD,
        #{pool := Pool} = H,
        ExpStr = case Expiry of
            connected -> "-";
            _ -> format_reltime(Expiry)
        end,
        Fields = [
            Hdl,
            User,
            Pool,
            Ip,
            St,
            format_reltime(Start),
            format_reltime(Min),
            ExpStr,
            io_lib:format("~w", [Pid])
        ],
        io:format(Fmt, Fields)
    end, HdlsSorted).

pool_list([]) ->
    {ok, Pools} = session_ra:get_all_pools(),
    {ok, Hosts} = session_ra:get_all_hosts(),
    Fmt = "~16.. s  ~30.. s  ~12.. s  ~7.. s  ~25.. s  ~14.. s  ~14.. s  "
        "~8.. s  ~8.. s\n",
    io:format(Fmt, ["ID", "TITLE", "MODE", "CHOICE", "ROLES", "MIN RSVD TIME",
        "HDL EXP TIME", "HOSTS#", "HDLS#"]),
    lists:foreach(fun (PD) ->
        #{id := Id, title := Title, mode := Mode, report_roles := Roles,
          min_rsvd_time := MinRsvdTime, hdl_expiry_time := HdlExpTime,
          choice := Choice} = PD,
        Hs = [H || H = #{pool := PoolId} <- Hosts, PoolId =:= Id],
        Hdls = lists:foldl(fun (#{handles := HostHdls}, Acc0) ->
            lists:foldl(fun (Hdl, Acc1) ->
                {ok, #{state := St}} = session_ra:get_handle(Hdl),
                case St of
                    ok -> [Hdl | Acc1];
                    _ -> Acc1
                end
            end, Acc0, HostHdls)
        end, [], Hs),
        RolesStr = case Roles of
            [] -> "-";
            _ -> string:join([unicode:characters_to_list(R, latin1) || R <- Roles], ",")
        end,
        Fields = [
            Id,
            Title,
            Mode,
            Choice,
            RolesStr,
            integer_to_list(MinRsvdTime),
            integer_to_list(HdlExpTime),
            integer_to_list(length(Hs)),
            integer_to_list(length(Hdls))
        ],
        io:format(Fmt, Fields)
    end, Pools).

pool_create([NameStr | Rest]) ->
    Id = list_to_atom(NameStr),
    {ok, M0} = parse_update_map(Rest, #{
        title => binary,
        help_text => binary,
        choice => atom,
        mode => atom,
        min_rsvd_time => integer,
        hdl_expiry_time => integer,
        priority => integer
    }),
    M1 = M0#{id => Id},
    Res = session_ra:create_pool(M1),
    io:format("~p\n", [Res]).

pool_get([NameStr]) ->
    Id = list_to_atom(NameStr),
    case session_ra:get_pool(Id) of
        {ok, PD} ->
            #{id := Id, title := Title, help_text := HelpText,
              acl := ACL, mode := Mode, report_roles := Roles,
              min_rsvd_time := MinRsvdTime, hdl_expiry_time := HdlExpTime,
              choice := Choice, role_priority := RolePrio} = PD,
            RolesStr = case Roles of
                [] -> "-";
                _ -> string:join([unicode:characters_to_list(R, latin1) || R <- Roles], ",")
            end,
            io:format("ID            ~s\n", [Id]),
            io:format("TITLE         ~s\n", [Title]),
            io:format("MODE          ~s\n", [Mode]),
            io:format("CHOICE        ~s\n", [Choice]),
            io:format("ROLES         ~s\n", [RolesStr]),
            io:format("TIMEOUTS      min_rsvd_time: ~B\n"
                      "              hdl_expiry_time: ~B\n",
                      [MinRsvdTime, HdlExpTime]),
            io:format("\nHELP TEXT:\n~s\n", [HelpText]),
            io:format("\nACL:\n"),
            lists:foreach(fun (AclEnt) ->
                io:format("  ~p\n", [AclEnt])
            end, ACL),
            io:format("\nROLE PRIORITY:\n"),
            lists:foreach(fun ({Role, Prio}) ->
                io:format("  ~s => ~B\n", [Role, Prio])
            end, maps:to_list(RolePrio));
        Err ->
            io:format("~p\n", [Err])
    end.

parse_update_map(List, Schema) ->
    parse_update_map(#{}, List, Schema).
parse_update_map(M0, [], _Schema) ->
    {ok, M0};
parse_update_map(M0, [Next | Rest], Schema) ->
    case string:split(Next, "=", leading) of
        [Key, Value0] ->
            KeyAtom = list_to_existing_atom(Key),
            case Schema of
                #{KeyAtom := integer} ->
                    Value1 = list_to_integer(Value0),
                    parse_update_map(M0#{KeyAtom => Value1}, Rest, Schema);
                #{KeyAtom := binary} ->
                    Value1 = unicode:characters_to_binary(Value0, utf8),
                    parse_update_map(M0#{KeyAtom => Value1}, Rest, Schema);
                #{KeyAtom := atom} ->
                    Value1 = list_to_atom(Value0),
                    parse_update_map(M0#{KeyAtom => Value1}, Rest, Schema);
                _ ->
                    {error, {unknown_update_key, KeyAtom}}
            end;
        _ ->
            {error, {invalid_map_kv, Next}}
    end.

pool_update([Id | Rest]) ->
    {ok, UpdateMap} = parse_update_map(Rest, #{
        title => binary,
        help_text => binary,
        choice => atom,
        mode => atom,
        min_rsvd_time => integer,
        hdl_expiry_time => integer,
        priority => integer
    }),
    Res = session_ra:update_pool(UpdateMap#{id => Id}),
    io:format("~p\n", [Res]).

host_update([Ip | Rest]) ->
    {ok, UpdateMap} = parse_update_map(Rest, #{
        hostname => binary,
        port => integer,
        pool => atom,
        idle_from => integer,
        image => binary,
        role => binary,
        hypervisor => binary,
        desc => binary,
        cert_verify => atom,
        forward_creds => atom
    }),
    case host_find(Ip) of
        {ok, #{ip := RealIp}} ->
            Res = session_ra:update_host(UpdateMap#{ip => RealIp}),
            io:format("~p\n", [Res]);
        Err ->
            io:format("~p\n", [Err])
    end.

alloc_pool([User]) ->
    {ok, Pools} = session_ra:get_pools_for(#{user => User, groups => []}),
    io:format("~p\n", [Pools]).

print_prefs(Prefs) ->
    Fmt = "~16.. s  ~18.. s  ~8.. s  ~30.. s  ~26.. s  ~26.. s  ~16.. s  ~16.. s  ~8.. s  "
        "~22.. s  ~13.. s\n",
    io:format(Fmt, ["IP", "HOST", "ENABLED", "LASTERR", "LASTUSER",
        "LASTREP", "SESSIONS", "IMAGE", "ROLE", "REPSTATE", "REPORT"]),
    lists:foreach(fun (Host) ->
        #{ip := Ip, hostname := Hostname, enabled := Ena, image := Img,
          role := Role, last_report := LastRep, handles := Hdls,
          report_state := {RepState, RepChanged}} = Host,
        #{error_history := EHist, alloc_history := AHist,
          session_history := SHist} = Host,
        LastErr = case queue:out_r(EHist) of
            {{value, #{time := ET, error := Err}}, _} ->
                iolist_to_binary([
                    io_lib:format("~14w", [Err]),
                    " (", format_reltime(ET), ")"]);
            _ -> "-"
        end,
        LastUser = case queue:out_r(AHist) of
            {{value, #{time := AT, user := U}}, _} ->
                iolist_to_binary([
                    U, " (", format_reltime(AT), ")"]);
            _ -> "-"
        end,
        LastSess = case queue:out_r(SHist) of
            {{value, #{time := ST, user := SU}}, _} ->
                iolist_to_binary([
                    SU, " (", format_reltime(ST), ")"]);
            _ -> "-"
        end,
        LastRepTxt = case LastRep of
            none -> "-";
            _ -> format_reltime(LastRep)
        end,
        RepStateTxt = io_lib:format("~w (~s)",
            [RepState, format_reltime(RepChanged)]),
        HDs = lists:foldl(fun (Hdl, Acc) ->
            case session_ra:get_handle(Hdl) of
                {ok, HD} -> [HD | Acc];
                _ -> Acc
            end
        end, [], Hdls),
        ActiveSess = length(lists:filter(fun
            (#{expiry := connected}) -> true;
            (_) -> false
        end, HDs)),
        ReadySess = length(lists:filter(fun
            (#{expiry := I}) when is_integer(I) -> true;
            (_) -> false
        end, HDs)),
        SessTxt = io_lib:format("~B act/~B rdy", [ActiveSess, ReadySess]),
        Fields = [
            Ip,
            Hostname,
            if Ena -> "true"; not Ena -> "false" end,
            LastErr,
            LastUser,
            LastSess,
            SessTxt,
            Img,
            Role,
            RepStateTxt,
            LastRepTxt
        ],
        io:format(Fmt, Fields)
    end, Prefs).

alloc_host([PoolStr, User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    Pool = list_to_atom(PoolStr),
    {ok, Prefs0} = session_ra:get_prefs(Pool, UserBin),
    Prefs1 = lists:map(fun(Ip) ->
        {ok, Host} = session_ra:get_host(Ip),
        Host
    end, Prefs0),
    print_prefs(Prefs1).

host_create([Pool, Ip]) ->
    PoolAtom = list_to_atom(Pool),
    IpBin = unicode:characters_to_binary(Ip, latin1),
    {ok, IpInet} = inet:parse_address(Ip),
    {ok, Hostname} = http_api:rev_lookup(IpInet),
    Ret = session_ra:create_host(#{
        pool => PoolAtom,
        ip => IpBin,
        hostname => iolist_to_binary([Hostname]),
        port => 3389}),
    io:format("~p\n", [Ret]);
host_create([Pool, Ip | Rest]) ->
    PoolAtom = list_to_atom(Pool),
    IpBin = unicode:characters_to_binary(Ip, latin1),
    {ok, M0} = parse_update_map(Rest, #{
        hostname => binary,
        port => integer,
        idle_from => integer,
        image => binary,
        role => binary,
        hypervisor => binary,
        desc => binary,
        cert_verify => atom,
        forward_creds => atom
    }),
    M1 = M0#{
        pool => PoolAtom,
        ip => IpBin
    },
    Ret = session_ra:create_host(M1),
    io:format("~p\n", [Ret]).

host_find(IpOrName) ->
    IpBin = unicode:characters_to_binary(IpOrName, latin1),
    case session_ra:get_host(IpBin) of
        {ok, H} -> {ok, H};
        {error, not_found} ->
            {ok, AllHosts} = session_ra:get_all_hosts(),
            Matches = lists:filter(fun (#{hostname := N}) ->
                case {N, catch binary:part(N, {0, byte_size(IpBin)})} of
                    {IpBin, _} -> true;
                    {_, IpBin} -> true;
                    _ -> false
                end
            end, AllHosts),
            case Matches of
                [H] -> {ok, H};
                [_ | _] -> {error, ambiguous};
                _ -> {error, not_found}
            end;
        OtherErr -> OtherErr
    end.

host_enable([Ip]) ->
    case host_find(Ip) of
        {ok, #{ip := RealIp}} ->
            Ret = session_ra:enable_host(RealIp),
            io:format("~p\n", [Ret]);
        Err ->
            io:format("~p\n", [Err])
    end.

host_disable([Ip]) ->
    case host_find(Ip) of
        {ok, #{ip := RealIp}} ->
            Ret = session_ra:disable_host(RealIp),
            io:format("~p\n", [Ret]);
        Err ->
            io:format("~p\n", [Err])
    end.

host_delete([Ip]) ->
    case host_find(Ip) of
        {ok, #{ip := RealIp}} ->
            Ret = session_ra:delete_host(RealIp),
            io:format("~p\n", [Ret]);
        Err ->
            io:format("~p\n", [Err])
    end.

host_get([Ip]) ->
    case host_find(Ip) of
        {ok, Host} ->
            #{ip := RealIp, hostname := Hostname, enabled := Ena, image := Img,
              pool := Pool, role := Role, last_report := LastRep,
              handles := Hdls, report_state := {RepState, RepChanged}} = Host,
            #{error_history := EHist, alloc_history := AHist,
              session_history := SHist} = Host,
            CertVerify = case Host of
                #{cert_verify := Override} -> io_lib:format("~p", [Override]);
                _ -> "default"
            end,
            ForwardCreds = case Host of
                #{forward_creds := FwdOverride} -> io_lib:format("~p", [FwdOverride]);
                _ -> "default"
            end,
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
            io:format("IP            ~s\n", [RealIp]),
            io:format("HOSTNAME      ~s\n", [Hostname]),
            io:format("POOL          ~s\n", [Pool]),
            io:format("ENABLED       ~p\n", [Ena]),
            io:format("IMAGE         ~s\n", [Img]),
            io:format("ROLE          ~s\n", [Role]),
            io:format("LAST REPORT   ~s\n", [LastRepTxt]),
            io:format("REPORT STATE  ~s\n", [RepStateTxt]),
            io:format("CERT VERIFY   ~s\n", [CertVerify]),
            io:format("FWD CREDS     ~s\n", [ForwardCreds]),
            io:format("\n"),
            Fmt = "~17.. s  ~16.. s  ~10.. s  ~20.. s  ~20.. s  ~20.. s  ~20.. s\n",
            io:format(Fmt, ["HANDLE", "USER", "STATE", "START", "MIN", "EXPIRY", "PID"]),
            lists:foreach(fun (Hdl) ->
                {ok, HD} = session_ra:get_handle(Hdl),
                #{user := User, start := Start, min := Min, pid := Pid,
                  expiry := Expiry, state := St} = HD,
                ExpStr = case Expiry of
                    connected -> "-";
                    _ -> format_reltime(Expiry)
                end,
                Fields = [
                    Hdl,
                    User,
                    St,
                    format_reltime(Start),
                    format_reltime(Min),
                    ExpStr,
                    io_lib:format("~w", [Pid])
                ],
                io:format(Fmt, Fields)
            end, Hdls),
            io:format("\nRECENT USERS\n"),
            lists:foreach(fun (#{time := AT, user := U}) ->
                io:format(" * ~s (~s)\n", [U, format_reltime(AT)])
            end, queue:to_list(AHist)),
            io:format("\nRECENT ERRORS\n"),
            lists:foreach(fun (#{time := ET, error := Err}) ->
                io:format(" * ~s:  ~p\n", [format_reltime(ET), Err])
            end, queue:to_list(EHist)),
            io:format("\nREPORTED SESSIONS\n"),
            lists:foreach(fun (#{time := ST, user := U, type := T}) ->
                io:format(" * ~s: ~s (~s)\n", [format_reltime(ST), U, T])
            end, queue:to_list(SHist));
        Err ->
            io:format("~p\n", [Err])
    end.

host_test([Ip]) ->
    {ok, #{ip := IpBin}} = host_find(Ip),
    {ok, Hdl, HD0} = session_ra:reserve_ip(<<"_admin_cli">>, IpBin),
    #{port := Port} = HD0,
    case backend:probe(binary_to_list(IpBin), Port) of
        ok ->
            HD1 = HD0#{password => <<"_admin_cli">>},
            {ok, _HD1} = session_ra:allocate(Hdl, HD1),
            io:format("probe returned ok (handle ~s)\n", [Hdl]);
        {error, Reason} ->
            io:format("error: ~p\n", [Reason]),
            session_ra:alloc_error(Hdl, Reason);
        Other ->
            io:format("error: ~p\n", [Other]),
            session_ra:alloc_error(Hdl, Other)
    end.

host_list(Args) ->
    {ok, Hosts0} = session_ra:get_all_hosts(),
    Hosts1 = case Args of
        [] -> Hosts0;
        [PoolName] ->
            PoolAtom = list_to_atom(PoolName),
            lists:filter(fun(Host) ->
                case Host of
                    #{pool := PoolAtom} -> true;
                    _ -> false
                end
            end, Hosts0)
    end,
    Hosts2 = lists:sort(fun(A, B) ->
        #{ip := IpA, pool := PoolA, enabled := EnaA,
          report_state := {RepStateA, _RepChangedA}} = A,
        #{ip := IpB, pool := PoolB, enabled := EnaB,
          report_state := {RepStateB, _RepChangedB}} = B,
        if
            PoolA < PoolB -> true;
            PoolA > PoolB -> false;
            EnaA and (not EnaB) -> true;
            (not EnaA) and EnaB -> false;
            RepStateA < RepStateB -> true;
            RepStateA > RepStateB -> false;
            IpA < IpB -> true;
            IpA > IpB -> false
        end
    end, Hosts1),
    Fmt = "~10.. s  ~16.. s  ~18.. s  ~8.. s  ~30.. s  ~26.. s  ~16.. s  "
        "~16.. s  ~8.. s  ~22.. s  ~13.. s\n",
    io:format(Fmt, ["POOL", "IP", "HOST", "ENABLED", "LASTERR", "LASTUSER",
        "SESSIONS", "IMAGE", "ROLE", "REPSTATE", "REPORT"]),
    lists:foreach(fun (Host) ->
        #{ip := Ip, pool := Pool, hostname := Hostname, enabled := Ena,
          image := Img, role := Role, last_report := LastRep, handles := Hdls,
          report_state := {RepState, RepChanged}} = Host,
        #{error_history := EHist, alloc_history := AHist} = Host,
        LastErr = case queue:out_r(EHist) of
            {{value, #{time := ET, error := Err}}, _} ->
                iolist_to_binary([
                    io_lib:format("~14w", [Err]),
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
        HDs = lists:foldl(fun (Hdl, Acc) ->
            case session_ra:get_handle(Hdl) of
                {ok, HD} -> [HD | Acc];
                _ -> Acc
            end
        end, [], Hdls),
        ActiveSess = length(lists:filter(fun
            (#{expiry := connected}) -> true;
            (_) -> false
        end, HDs)),
        ReadySess = length(lists:filter(fun
            (#{expiry := I}) when is_integer(I) -> true;
            (_) -> false
        end, HDs)),
        SessTxt = io_lib:format("~B act/~B rdy", [ActiveSess, ReadySess]),
        Fields = [
            Pool,
            Ip,
            Hostname,
            if Ena -> "true"; not Ena -> "false" end,
            LastErr,
            LastUser,
            SessTxt,
            Img,
            Role,
            RepStateTxt,
            LastRepTxt
        ],
        io:format(Fmt, Fields)
    end, Hosts2).

conn_list(["-j"]) ->
    {ok, Conns} = conn_ra:get_all_open(),
    lists:foreach(fun (Conn) ->
        Conn1 = case Conn of
            #{stopped := _} -> Conn;
            _ -> Conn#{stopped => erlang:system_time(second)}
        end,
        io:format("~s", [conn_ra_v2:conn_to_json(Conn1)])
    end, Conns);

conn_list([]) ->
    {ok, Conns} = conn_ra:get_all_open(),
    Fmt = "~16.. s  ~24.. s  ~10.. s  ~16.. s  ~19.. s  ~10.. s  ~16.. s  ~15.. s  "
        "~10.. s  ~8.. s  ~14.. s  ~11.. s  ~6.. s  ~5.. s  ~6.. s\n",
    io:format(Fmt, ["ID", "PEER", "NODE", "PID", "STARTED", "USER", "HANDLE",
        "BACKEND", "POOL", "PROTVER", "REMHOST", "RES", "RECONN", "TSESS", "END"]),
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
          session := S = #{user := U, ip := Backend}} = Conn,
        Hdl = case S of
            #{handle := HH} -> HH;
            _ -> <<"-">>
        end,
        BackendText = case Conn of
            #{ui_fsm := _} when (Backend =/= undefined) -> [Backend, "*"];
            _ when (Backend =:= undefined) -> "";
            _ -> Backend
        end,
        PoolTxt = case Backend of
            undefined -> "-";
            _ ->
                {ok, #{pool := Pool}} = session_ra:get_host(Backend),
                io_lib:format("~p", [Pool])
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
                        Reconn = "-";
                    undefined ->
                        Reconn = "-";
                    _ when (TsudCluster#tsud_cluster.sessionid =:= none) ->
                        Reconn = "yes";
                    _ ->
                        Reconn = "+yes"
                end;
            _ ->
                ProtVer = "",
                Client = "",
                Res = "",
                Reconn = ""
        end,
        TSess = case Conn of
            #{ts_session_id := SId, ts_session_status := _} when is_integer(SId) ->
                io_lib:format("+~B", [SId]);
            #{ts_session_id := SId} when is_integer(SId) ->
                io_lib:format("~B", [SId]);
            _ ->
                "-"
        end,
        End = case Conn of
            #{ts_error_info := {error, driver_crash}} ->
                "ERR:dr";
            #{ts_error_info := {error, driver_iface}} ->
                "ERR:dr";
            #{ts_error_info := {error, driver_timeout}} ->
                "ERR:dr";
            #{ts_error_info := {error, _Why}} ->
                "ERR";
            #{ts_error_info := {denied, _Why}} ->
                "DENY";
            #{ts_error_info := {logoff, Why}} when (Why =:= normal) or (Why =:= client) ->
                "L:ok";
            #{ts_error_info := {disconnect, Why}} when (Why =:= normal) or (Why =:= client) ->
                "D:ok";
            #{ts_error_info := {logoff, admin}} ->
                "L:adm";
            #{ts_error_info := {disconnect, admin}} ->
                "D:adm";
            #{ts_error_info := {logoff, user_on_server}} ->
                "L:usr";
            #{ts_error_info := {disconnect, user_on_server}} ->
                "D:usr";
            #{ts_error_info := {disconnect, other_conn}} ->
                "D:repl";
            #{ts_error_info := {logoff, Why}} when (Why =:= idle) or (Why =:= timelimit) ->
                "L:time";
            #{ts_error_info := _} ->
                "?";
            _ ->
                "-"
        end,
        Fields = [
            Id,
            Peer,
            Node,
            io_lib:format("~w", [Pid]),
            format_reltime(Started),
            U,
            Hdl,
            BackendText,
            PoolTxt,
            ProtVer,
            Client,
            Res,
            Reconn,
            TSess,
            End
        ],
        io:format(Fmt, Fields)
    end, ConnsSorted),
    io:format("count: ~B\n", [length(Conns)]).

conn_user(["-j", User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    {ok, Conns} = conn_ra:get_user(UserBin),
    lists:foreach(fun (Conn) ->
        Conn1 = case Conn of
            #{stopped := _} -> Conn;
            _ -> Conn#{stopped => erlang:system_time(second)}
        end,
        io:format("~s", [conn_ra_v2:conn_to_json(Conn1)])
    end, Conns);

conn_user(["-v", User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    {ok, Conns} = conn_ra:get_user(UserBin),
    Fmt = "~12.. s  ~25.. s  ~14.. s  ~14.. s  ~15.. s  ~8.. s  ~10.. s  "
        "~10.. s  ~9.. s\n",
    lists:foreach(fun (Conn) ->
        #{id := Id, started := Started, peer := {Ip, Port},
          session := #{ip := Backend}} = Conn,
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
        io:format("  TSUDS:\n"),
        lists:foreach(fun (Tsud) ->
            io:format("    * ~s\n", [tsud:pretty_print(Tsud)])
        end, Tsuds),
        case Conn of
            #{ts_info := TsInfoV} ->
                io:format("  TS_INFO: ~s\n", [rdpp:pretty_print(TsInfoV)]);
            _ -> ok
        end,
        case Conn of
            #{ts_caps := TsCaps} ->
                io:format("  TS_CAPS:\n"),
                lists:foreach(fun (TsCap) ->
                    io:format("    * ~s\n", [rdpp:pretty_print(TsCap)])
                end, TsCaps);
            _ -> ok
        end
    end, Conns);

conn_user([User]) ->
    UserBin = unicode:characters_to_binary(User, utf8),
    {ok, Conns} = conn_ra:get_user(UserBin),
    Fmt = "~12.. s  ~16.. s  ~14.. s  ~24.. s  ~19.. s  ~10.. s  ~10.. s  ~15.. s  "
        "~8.. s  ~14.. s  ~11.. s  ~6.. s  ~5.. s  ~6.. s\n",
    io:format(Fmt, ["ID", "PID", "NODE", "PEER", "STARTED", "DURATION", "USER",
        "BACKEND", "PROTVER", "REMHOST", "RES", "RECONN", "TSESS", "END"]),
    lists:foreach(fun (Conn) ->
        #{id := Id, frontend_pid := Pid, started := Started,
          peer := {Ip, Port}, session := #{user := U, ip := Backend}} = Conn,
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
                        Reconn = "-";
                    undefined ->
                        Reconn = "-";
                    _ when (TsudCluster#tsud_cluster.sessionid =:= none) ->
                        Reconn = "yes";
                    _ ->
                        Reconn = "+yes"
                end;
            _ ->
                ProtVer = "",
                RemHost = "",
                Res = "",
                Reconn = ""
        end,
        Duration = case Conn of
            #{stopped := Stopped} -> format_deltatime(Stopped - Started, false);
            _ -> "-"
        end,
        TSess = case Conn of
            #{ts_session_id := SId, ts_session_status := _} when is_integer(SId) ->
                io_lib:format("+~B", [SId]);
            #{ts_session_id := SId} when is_integer(SId) ->
                io_lib:format("~B", [SId]);
            _ ->
                "-"
        end,
        End = case Conn of
            #{ts_error_info := {error, driver_crash}} ->
                "ERR:dr";
            #{ts_error_info := {error, driver_iface}} ->
                "ERR:dr";
            #{ts_error_info := {error, driver_timeout}} ->
                "ERR:dr";
            #{ts_error_info := {error, _Why}} ->
                "ERR";
            #{ts_error_info := {denied, _Why}} ->
                "DENY";
            #{ts_error_info := {logoff, Why}} when (Why =:= normal) or (Why =:= client) ->
                "L:ok";
            #{ts_error_info := {disconnect, Why}} when (Why =:= normal) or (Why =:= client) ->
                "D:ok";
            #{ts_error_info := {logoff, admin}} ->
                "L:adm";
            #{ts_error_info := {disconnect, admin}} ->
                "D:adm";
            #{ts_error_info := {logoff, user_on_server}} ->
                "L:usr";
            #{ts_error_info := {disconnect, user_on_server}} ->
                "D:usr";
            #{ts_error_info := {disconnect, other_conn}} ->
                "D:repl";
            #{ts_error_info := {logoff, Why}} when (Why =:= idle) or (Why =:= timelimit) ->
                "L:time";
            #{ts_error_info := _} ->
                "?";
            _ ->
                "-"
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
            Reconn,
            TSess,
            End
        ],
        io:format(Fmt, Fields)
    end, Conns).

dump_sessions([]) ->
    {ok, {_, SBin}, _} = ra:leader_query(session_ra,
        fun (S) -> erlang:term_to_binary(S) end),
    io:format("~s\n", [base64:encode(SBin)]).

dump_conns([]) ->
    {ok, {_, SBin}, _} = ra:leader_query(conn_ra,
        fun (S) -> erlang:term_to_binary(S) end),
    io:format("~s\n", [base64:encode(SBin)]);

dump_conns(["-j"]) ->
    {ok, {_, ConnMap}, _} = ra:leader_query(conn_ra,
        fun (S) -> element(4, S) end),
    lists:foreach(fun (Conn) ->
        Conn1 = case Conn of
            #{stopped := _} -> Conn;
            _ -> Conn#{stopped => erlang:system_time(second)}
        end,
        io:format("~s", [conn_ra_v2:conn_to_json(Conn1)])
    end, maps:values(ConnMap)).

port_recv_exit_status(Port) ->
    receive
        {Port, {data, _}} -> port_recv_exit_status(Port);
        {Port, {exit_status, N}} -> N
    end.

pool_reprobe([PoolName]) ->
    PoolAtom = list_to_atom(PoolName),
    {ok, {_, S}, _} = ra:leader_query(session_ra, fun (S) -> S end),
    Annotes = session_ra:annotate_prefs(4, PoolAtom, <<"_nobody">>, S),
    Errors = [A || #{in_error := true} = A <- Annotes],
    lists:foreach(fun (#{ip := Ip}) ->
        Cmd = iolist_to_binary(["ping -W 1 -q -c 1 ", Ip]),
        P = erlang:open_port({spawn, Cmd}, [exit_status]),
        case port_recv_exit_status(P) of
            0 ->
                {ok, Hdl, HD0} = session_ra:reserve_ip(<<"_admin_cli">>, Ip),
                #{port := Port} = HD0,
                case backend:probe(binary_to_list(Ip), Port) of
                    ok ->
                        HD1 = HD0#{password => <<"_admin_cli">>},
                        {ok, _HD1} = session_ra:allocate(Hdl, HD1),
                        io:format("~s: probe returned ok (handle ~s)\n", [Ip,
                            Hdl]);
                    {error, Reason} ->
                        io:format("~s: probe error: ~p\n", [Ip, Reason]),
                        session_ra:alloc_error(Hdl, Reason);
                    Other ->
                        io:format("~s: probe error: ~p\n", [Ip, Other]),
                        session_ra:alloc_error(Hdl, Other)
                end;
            _ ->
                io:format("~s: not responding to ping\n", [Ip])
        end
    end, Errors).

pool_errors([PoolName]) ->
    pool_errors([PoolName, "168"]);
pool_errors([PoolName, HoursStr]) ->
    Hours = list_to_integer(HoursStr),
    PoolAtom = list_to_atom(PoolName),
    {ok, {_, S0}, _} = ra:leader_query(session_ra, fun (S) -> S end),
    M0 = element(3, S0),
    M1 = maps:fold(fun (IP, HM0, Acc) ->
        HM1 = HM0#{enabled => true},
        Acc#{IP => HM1}
    end, #{}, M0),
    S1 = setelement(3, S0, M1),
    Annotes = session_ra:annotate_prefs(4, PoolAtom, <<"_nobody">>, S1),
    Errors = [A || #{in_error := true} = A <- Annotes],
    T0 = erlang:system_time(second) - 3600*Hours,
    Recent = [A || A = #{e_latest := E} <- Errors, E >= T0],
    ErrGroups = lists:foldl(fun (#{ip := IP}, Acc) ->
        #{error_history := EH} = maps:get(IP, M1),
        EHL = queue:to_list(EH),
        Errs = lists:usort([E || #{error := E, time := T} <- EHL, T >= T0]),
        L0 = maps:get(Errs, Acc, []),
        Acc#{Errs => [IP | L0]}
    end, #{}, Recent),
    lists:foreach(fun ({UErrs, IPs}) ->
        io:format("=== ~p ===\n", [UErrs]),
        lists:foreach(fun (IP) ->
            #{hostname := Hostname, alloc_history := AH} = maps:get(IP, M1),
            Users = lists:usort([U || #{user := U} <- queue:to_list(AH)]),
            io:format("~s\t~s\t~s\n", [IP, Hostname,
                iolist_to_binary(lists:join($,, Users))])
        end, IPs),
        io:format("\n")
    end, maps:to_list(ErrGroups)).

format_reltime(Time) -> format_reltime(Time, true).
format_reltime(Time, Flavour) ->
    Now = erlang:system_time(second),
    Delta = Now - Time,
    if
        (Delta > 12*3600) ->
            calendar:system_time_to_rfc3339(Time, [
                {time_designator, $ },
                {unit, second}]);
        true ->
            format_deltatime(Delta, Flavour)
    end.

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
