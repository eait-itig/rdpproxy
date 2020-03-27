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

-module(pool_ra).
-behaviour(ra_machine).

-include("session.hrl").

-export([init/1, apply/3]).
-export([start/0]).
-export([expire/0, create/3, enable/1, disable/1, update/2]).
-export([get_host/1, get_prefs/1, get_all_hosts/0]).
-export([reserve/1, allocate/1, alloc_error/2, add_session/2, status_report/2]).
-export([host_error/2]).
-export([get_reservation/1, get_reservations_for/1]).

start() ->
    Config = application:get_env(rdpproxy, ra, []),
    Nodes = proplists:get_value(nodes, Config, [node() | nodes()]),
    Servers = [{pool_ra, N} || N <- Nodes],
    ra:start_or_restart_cluster("pool_ra", {module, ?MODULE, #{}}, Servers).

expire() ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {expire, Now}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

create(Ip, Hostname, Port) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {create, Now, Ip, Hostname, Port}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

enable(Ip) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {enable, Now, Ip}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

disable(Ip) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {disable, Now, Ip}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

update(Ip, ChangeMap) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {update, Now, Ip, ChangeMap}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get_host(Ip) ->
    case ra:process_command(pool_ra, {get_host, Ip}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get_prefs(User) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {get_prefs, Now, User}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get_reservation(Hdl) ->
    case ra:process_command(pool_ra, {get_reservation, Hdl}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get_reservations_for(User) ->
    case ra:process_command(pool_ra, {get_reservations, User}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

reserve(User) ->
    PoolPrefs = maps:from_list(application:get_env(rdpproxy, pool, [])),
    T = erlang:system_time(second),
    TM = T + maps:get(min_rsvd_time, PoolPrefs, 900),
    TE = T + maps:get(rsv_expire_time, PoolPrefs, ?COOKIE_TTL),
    Hdl = cookie_ra:gen_key(),
    case ra:process_command(pool_ra, {reserve, {T, TM, TE}, Hdl, User}) of
        {ok, {error, duplicate_handle}, _Leader} -> reserve(User);
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

allocate(Hdl) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {allocate, Now, Hdl}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

alloc_error(Hdl, Err) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {alloc_error, Now, Hdl, Err}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

host_error(Ip, Err) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {host_error, Now, Ip, Err}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

get_all_hosts() ->
    case ra:process_command(pool_ra, get_all_hosts) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

add_session(Ip, SessMap) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {add_session, Now, Ip, SessMap}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

status_report(Ip, State) ->
    Now = erlang:system_time(second),
    case ra:process_command(pool_ra, {status_report, Now, Ip, State}) of
        {ok, Ret, _Leader} -> Ret;
        Else -> Else
    end.

-define(HISTORY_LIMIT, 16).

-record(state, {
    meta = #{},
    users = #{},
    hdls = #{},
    hdlexp = queue:new(),
    prefs = []
    }).

% meta: #{<<"1.2.3.4">> => #{
%     ip => <<"1.2.3.4">>,
%     hostname => <<"gs123-1234">>,
%     port => 3389,
%     enabled => true,

%     reserved => <<"hdl cookie">>,
%
%     error_history => queue:new(),
        % last N error reports from probes or connections
        % #{time => Seconds, error => Err}
%     alloc_history => queue:new(),
        % last N successful allocations, look like
        % #{time => Seconds, user => <<"user">>, hdl => <<"random">>}
%     session_history => queue:new(),
        % last N sessions from status reports, look like
        % #{time => Seconds, user => <<"user">>, type => <<"rdp">> | <<"console">>}
%     report_state => {busy | available, FromSeconds},
%     last_report => Seconds,
%     idle_from => Seconds, % timestamp of last idle status report
%
%     image => <<"lab20191201">>, % might be from status reports
%     role => <<"vlab">>,
% }}
% users: #{<<"username">> => queue:new() of handle}
% hdls: #{<<"cookie">> => #{
%     time => Seconds, min => Seconds, expiry => Seconds,
%     user => User, ip => Ip, state => in_progress | done | error}}
% prefs: [<<"1.2.3.4">>, <<"1.2.3.5">>] % prefs list for new allocations, sorted

init(_Config) ->
    #state{}.

apply(#{index := Idx}, {expire, T}, S0 = #state{}) ->
    S1 = expire_hdls(T, S0),
    S2 = regen_prefs(S1),
    {S2, ok, [{release_cursor, Idx, S2}]};

apply(_Meta, get_all_hosts, S0 = #state{meta = M0}) ->
    {S0, {ok, maps:values(M0)}, []};

apply(_Meta, {get_reservation, Hdl}, S0 = #state{hdls = H0}) ->
    case H0 of
        #{Hdl := HD} ->
            {S0, {ok, HD}, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {get_reservations, User}, S0 = #state{users = U0, hdls = H0}) ->
    case U0 of
        #{User := HdlQ} ->
            Hdls = lists:map(fun (Hdl) ->
                case H0 of
                    #{Hdl := HD} -> HD#{handle => Hdl};
                    _ -> #{handle => Hdl}
                end
            end, queue:to_list(HdlQ)),
            {S0, {ok, Hdls}, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {create, T, Ip, Hostname, Port}, S0 = #state{meta = M0})
        when is_binary(Hostname) and is_integer(Port) ->
    case M0 of
        #{Ip := _} ->
            {S0, {error, duplicate_ip}, []};
        _ ->
            M1 = M0#{Ip => #{
                ip => Ip,
                hostname => Hostname,
                port => Port,
                enabled => false,

                error_history => queue:new(),
                alloc_history => queue:new(),
                session_history => queue:new(),
                idle_from => none,
                last_update => none,
                report_state => {available, T},
                last_report => none,

                image => none,
                role => none,
                hypervisor => unknown
            }},
            S1 = S0#state{meta = M1},
            {S1, ok, []}
    end;

apply(_Meta, {enable, _T, Ip}, S0 = #state{meta = M0}) ->
    case M0 of
        #{Ip := #{enabled := true}} ->
            {S0, {error, already_enabled}, []};
        #{Ip := HM0 = #{enabled := false}} ->
            HM1 = HM0#{enabled => true},
            M1 = M0#{Ip => HM1},
            S1 = regen_prefs(S0#state{meta = M1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {disable, _T, Ip}, S0 = #state{meta = M0}) ->
    case M0 of
        #{Ip := #{enabled := false}} ->
            {S0, {error, already_disabled}, []};
        #{Ip := HM0 = #{enabled := true}} ->
            HM1 = HM0#{enabled => false},
            M1 = M0#{Ip => HM1},
            S1 = regen_prefs(S0#state{meta = M1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {update, T, Ip, CM}, S0 = #state{meta = M0}) when is_map(CM) ->
    case M0 of
        #{Ip := HM0} ->
            HM1 = maps:map(fun (K, V0) ->
                case {K, CM} of
                    {hostname, #{K := V1}} when is_binary(V1) -> V1;
                    {port, #{K := V1}} when is_integer(V1) -> V1;
                    {idle_from, #{K := V1}} when is_integer(V1) -> V1;
                    {image, #{K := V1}} when is_binary(V1) -> V1;
                    {role, #{K := V1}} when is_binary(V1) -> V1;
                    {hypervisor, #{K := V1}} when is_binary(V1) -> V1;
                    _ -> V0
                end
            end, HM0),
            HM2 = HM1#{last_update => T},
            M1 = M0#{Ip => HM2},
            S1 = regen_prefs(S0#state{meta = M1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {get_prefs, T, User}, S0 = #state{}) ->
    Prefs = case user_existing_hosts(User, S0) of
        P = [_Ip | _] -> P;
        _ ->
            case filter_reserved_hosts(T, User, min, S0) of
                P = [_Ip | _] -> P;
                [] ->
                    case filter_reserved_hosts(T, User, expiry, S0) of
                        P = [_Ip | _] -> P;
                        [] -> []
                    end
            end
    end,
    {S0, {ok, Prefs}, []};

apply(_Meta, {get_host, Ip}, S0 = #state{meta = M0}) ->
    case M0 of
        #{Ip := HM} -> {S0, {ok, HM}, []};
        _ -> {S0, {error, not_found}, []}
    end;

apply(_Meta, {reserve, {T, TM, TE}, Hdl, User}, S0 = #state{meta = M0, users = U0, hdls = H0}) ->
    case H0 of
        #{Hdl := _} ->
            {S0, {error, duplicate_handle}, []};
        _ ->
            case user_existing_hosts(User, S0) of
                [Ip | _] ->
                    S1 = begin_hdl(Hdl, User, Ip, {T, TM, TE}, S0),
                    #{Ip := #{port := Port}} = M0,
                    {S1, {ok, Hdl, Ip, Port}, []};
                _ ->
                    case filter_reserved_hosts(T, User, min, S0) of
                        [Ip | _] ->
                            S1 = begin_hdl(Hdl, User, Ip, {T, TM, TE}, S0),
                            #{Ip := #{port := Port}} = M0,
                            {S1, {ok, Hdl, Ip, Port}, []};
                        [] ->
                            case filter_reserved_hosts(T, User, expiry, S0) of
                                [Ip | _] ->
                                    S1 = begin_hdl(Hdl, User, Ip, {T, TM, TE}, S0),
                                    #{Ip := #{port := Port}} = M0,
                                    {S1, {ok, Hdl, Ip, Port}, []};
                                [] ->
                                    {S0, {error, no_hosts}, []}
                            end
                    end
            end
    end;

apply(_Meta, {allocate, T, Hdl}, S0 = #state{meta = M0, hdls = H0}) ->
    case H0 of
        #{Hdl := HD0 = #{ip := Ip, user := User}} ->
            #{Ip := HM0} = M0,
            #{alloc_history := AHist0} = HM0,
            AHist1 = queue:in(#{time => T, user => User, hdl => Hdl}, AHist0),
            AHist2 = case queue:len(AHist1) of
                N when (N > ?HISTORY_LIMIT) ->
                    {{value, _}, Q} = queue:out(AHist1),
                    Q;
                _ -> AHist1
            end,
            HM1 = HM0#{alloc_history => AHist2},
            M1 = M0#{Ip => HM1},
            HD1 = HD0#{state => done},
            H1 = H0#{Hdl => HD1},
            S1 = regen_prefs(S0#state{meta = M1, hdls = H1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {alloc_error, T, Hdl, Err}, S0 = #state{meta = M0, hdls = H0}) ->
    case H0 of
        #{Hdl := HD0 = #{ip := Ip, user := User}} ->
            #{Ip := HM0} = M0,
            #{error_history := EHist0} = HM0,
            EHist1 = queue:in(#{time => T, error => Err}, EHist0),
            EHist2 = case queue:len(EHist1) of
                N when (N > ?HISTORY_LIMIT) ->
                    {{value, _}, Q} = queue:out(EHist1),
                    Q;
                _ -> EHist1
            end,
            HM1 = HM0#{error_history => EHist2},
            M1 = M0#{Ip => HM1},
            HD1 = HD0#{state => error},
            H1 = H0#{Hdl => HD1},
            S1 = regen_prefs(S0#state{meta = M1, hdls = H1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {host_error, T, Ip, Err}, S0 = #state{meta = M0}) ->
    case M0 of
        #{Ip := HM0 = #{error_history := EHist0}} ->
            EHist1 = queue:in(#{time => T, error => Err}, EHist0),
            EHist2 = case queue:len(EHist1) of
                N when (N > ?HISTORY_LIMIT) ->
                    {{value, _}, Q} = queue:out(EHist1),
                    Q;
                _ -> EHist1
            end,
            HM1 = HM0#{error_history => EHist2},
            M1 = M0#{Ip => HM1},
            S1 = regen_prefs(S0#state{meta = M1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {add_session, T, Ip, SessMap}, S0 = #state{meta = M0}) ->
    case M0 of
        #{Ip := HM0 = #{session_history := SHist0}} ->
            SHist1 = queue:in(SessMap, SHist0),
            SHist2 = case queue:len(SHist1) of
                N when (N > ?HISTORY_LIMIT) ->
                    {{value, _}, Q} = queue:out(SHist1),
                    Q;
                _ -> SHist1
            end,
            HM1 = HM0#{session_history => SHist2},
            M1 = M0#{Ip => HM1},
            S1 = regen_prefs(S0#state{meta = M1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, {status_report, T, Ip, State}, S0 = #state{meta = M0}) ->
    case M0 of
        #{Ip := HM0 = #{report_state := {State, _}}} ->
            HM1 = HM0#{last_report => T},
            M1 = M0#{Ip => HM1},
            S1 = regen_prefs(S0#state{meta = M1}),
            {S1, ok, []};
        #{Ip := HM0} ->
            HM1 = HM0#{report_state => {State, T}, last_report => T},
            M1 = M0#{Ip => HM1},
            S1 = regen_prefs(S0#state{meta = M1}),
            {S1, ok, []};
        _ ->
            {S0, {error, not_found}, []}
    end;

apply(_Meta, Cmd, S0 = #state{}) ->
    {S0, {error, not_impl}, []}.

expire_hdls(T, S0 = #state{hdls = H0, hdlexp = HQ0}) ->
    case queue:out(HQ0) of
        {{value, Hdl}, HQ1} ->
            case H0 of
                #{Hdl := #{expiry := TE}} when (T > TE) ->
                    H1 = maps:remove(Hdl, H0),
                    S1 = S0#state{hdls = H1, hdlexp = HQ1},
                    expire_hdls(T, S1);
                _ -> S0
            end;
        _ -> S0
    end.

begin_hdl(Hdl, User, Ip, {T, TM, TE}, S0 = #state{meta = M0, users = U0, hdls = H0, hdlexp = HQ0}) ->
    #{Ip := HM0} = M0,
    HM1 = HM0#{reservation => Hdl},
    M1 = M0#{Ip => HM1},

    U1 = case U0 of
        #{User := UH0} ->
            UH1 = queue:in(Hdl, UH0),
            U0#{User => UH1};
        _ ->
            UH0 = queue:from_list([Hdl]),
            U0#{User => UH0}
    end,

    H1 = H0#{Hdl => #{
        time => T, min => TM, expiry => TE, user => User, ip => Ip,
        state => in_progress}},
    HQ1 = queue:in(Hdl, HQ0),

    S0#state{meta = M1, users = U1, hdls = H1, hdlexp = HQ1}.

user_existing_hosts(User, S0 = #state{meta = M0, users = U0, hdls = H0}) ->
    case U0 of
        #{User := UH0} ->
            LastHMs = lists:foldl(fun (Hdl, Acc) ->
                case H0 of
                    #{Hdl := HD = #{ip := Ip}} ->
                        Acc#{Ip => {Hdl, HD}};
                    _ -> Acc
                end
            end, #{}, queue:to_list(UH0)),
            maps:fold(fun
                (Ip, {Hdl, HD = #{state := done}}, Acc) ->
                    case M0 of
                        #{Ip := HM0 = #{enabled := true, reservation := Hdl}} ->
                            [Ip | Acc];
                        _ -> Acc
                    end;
                (_Ip, _, Acc) -> Acc
            end, [], LastHMs);
        _ -> []
    end.

filter_reserved_hosts(T, User, ExpMin, S0 = #state{meta = M0, hdls = H0, prefs = Prefs}) ->
    lists:filter(fun (Ip) ->
        #{Ip := HM} = M0,
        case HM of
            #{enabled := false} -> false;
            #{reservation := Hdl} ->
                case H0 of
                    #{Hdl := #{user := User}} -> true;
                    #{Hdl := #{state := error}} -> true;
                    #{Hdl := #{ExpMin := TE}} when (T > TE) -> true;
                    #{Hdl := _} -> false;
                    _ -> true
                end;
            _ -> true
        end
    end, Prefs).

regen_prefs(S0 = #state{meta = M, hdls = H}) ->
    SortFun = fun(IpA, IpB) ->
        #{IpA := A, IpB := B} = M,
        #{role := RoleA, image := ImageA, idle_from := IdleFromA} = A,
        #{role := RoleB, image := ImageB, idle_from := IdleFromB} = B,

        #{error_history := EHistA, alloc_history := AHistA,
          session_history := SHistA} = A,
        ELatestA = case queue:out_r(EHistA) of
            {{value, #{time := ELAT}}, _} -> ELAT;
            _ -> 0
        end,
        ALatestA = case queue:out_r(AHistA) of
            {{value, #{time := ALAT}}, _} -> ALAT;
            _ -> 0
        end,
        SLatestA = case queue:out_r(SHistA) of
            {{value, #{time := SLAT}}, _} -> SLAT;
            _ -> 0
        end,
        SALatestA = lists:max([ALatestA, SLatestA]),

        #{error_history := EHistB, alloc_history := AHistB,
          session_history := SHistB} = B,
        ELatestB = case queue:out_r(EHistB) of
            {{value, #{time := ELBT}}, _} -> ELBT;
            _ -> 0
        end,
        ALatestB = case queue:out_r(AHistB) of
            {{value, #{time := ALBT}}, _} -> ALBT;
            _ -> 0
        end,
        SLatestB = case queue:out_r(SHistB) of
            {{value, #{time := SLBT}}, _} -> SLBT;
            _ -> 0
        end,
        SALatestB = lists:max([ALatestB, SLatestB]),

        InErrorA = (ELatestA > ALatestA),
        InErrorB = (ELatestB > ALatestB),

        #{report_state := {RepStateA, RepStateChangedA}} = A,
        #{report_state := {RepStateB, RepStateChangedB}} = B,
        #{last_report := LastRepA} = A,
        #{last_report := LastRepB} = B,

        IsLabA = if
            is_binary(ImageA) ->
                (binary:longest_common_prefix([ImageA, <<"lab">>]) =/= 0);
            true -> false
        end,
        IsLabB = if
            is_binary(ImageB) ->
                (binary:longest_common_prefix([ImageB, <<"lab">>]) =/= 0);
            true -> false
        end,

        ReservedA = case A of
            #{reservation := HdlA} ->
                case H of
                    #{HdlA := #{state := error}} -> false;
                    #{HdlA := _} -> true;
                    _ -> false
                end;
            _ -> false
        end,
        ReservedB = case B of
            #{reservation := HdlB} ->
                case H of
                    #{HdlB := #{state := error}} -> false;
                    #{HdlB := _} -> true;
                    _ -> false
                end;
            _ -> false
        end,

        % A <= B  => true
        % else    => false
        %
        % lists:sort sorts ascending, and we are going to start at the front,
        % so more preferred => return true
        if
            % prefer machines where the latest event wasn't an error
            (not InErrorA) and InErrorB -> true;
            InErrorA and (not InErrorB) -> false;
            % prefer machines with role == vlab
            (RoleA =:= <<"vlab">>) and (not (RoleB =:= <<"vlab">>)) -> true;
            (not (RoleA =:= <<"vlab">>)) and (RoleB =:= <<"vlab">>) -> false;
            % prefer lab images
            IsLabA and (not IsLabB) -> true;
            (not IsLabA) and IsLabB -> false;
            % prefer recent images
            (ImageA > ImageB) -> true;
            (ImageA < ImageB) -> false;
            % prefer machines without a current reservation
            ReservedA and (not ReservedB) -> true;
            (not ReservedA) and ReservedB -> false;
            % prefer machines whose last status report was not busy
            (RepStateA =:= available) and (RepStateB =:= busy) -> true;
            (RepStateA =:= busy) and (RepStateB =:= available) -> false;
            % prefer machines where the status report changed furthest in the
            % past (to precision of 2 hrs)
            (LastRepA =/= none) and (LastRepB =/= none) and
                (RepStateChangedA div 7200) < (RepStateChangedB div 7200) -> true;
            (LastRepA =/= none) and (LastRepB =/= none) and
                (RepStateChangedA div 7200) > (RepStateChangedB div 7200) -> false;
            % prefer machines where the last alloc or session start was further
            % in the past (to a precision of 2 hrs, so if in the same 2hour
            % we use idle, then if idle is the same, we come back to this)
            (SALatestA =/= 0) and (SALatestB =/= 0) and
                (SALatestA div 7200) < (SALatestB div 7200) -> true;
            (SALatestA =/= 0) and (SALatestB =/= 0) and
                (SALatestA div 7200) > (SALatestB div 7200) -> false;
            % prefer machines that have been idle longest (to a precision of
            % 5 mins)
            (not (IdleFromA =:= none)) and (not (IdleFromB =:= none)) and
                (IdleFromA div 300) < (IdleFromB div 300) -> true;
            (not (IdleFromA =:= none)) and (not (IdleFromB =:= none)) and
                (IdleFromA div 300) > (IdleFromB div 300) -> false;
            % last alloc or session start further in the past, cont.
            (SALatestA =/= 0) and (SALatestB =/= 0) and
                (SALatestA < SALatestB) -> true;
            (SALatestA =/= 0) and (SALatestB =/= 0) and
                (SALatestA > SALatestB) -> false;
            % last error further in the past
            (ELatestA < ELatestB) -> true;
            (ELatestA > ELatestB) -> false;
            % failing everything else, sort by IP
            (IpA < IpB) -> true;
            (IpA > IpB) -> false
        end
    end,
    Ips = maps:fold(fun (Ip, HM, Acc) ->
        case HM of
            #{enabled := true} -> [Ip | Acc];
            _ -> Acc
        end
    end, [], M),
    S0#state{prefs = lists:sort(SortFun, Ips)}.
