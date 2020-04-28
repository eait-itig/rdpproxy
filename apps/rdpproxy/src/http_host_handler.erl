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

-module(http_host_handler).
-behaviour(cowboy_handler).

-export([init/2]).
-export([allowed_methods/2, forbidden/2, content_types_provided/2, resource_exists/2,
         content_types_accepted/2]).
-export([from_json/2, to_json/2]).

-record(state, {opts, ip, meta, peer}).

init(Req, Opts) ->
    IpBin = cowboy_req:binding(ip, Req),
    {cowboy_rest, Req, #state{opts = Opts, ip = IpBin}}.

allowed_methods(Req, S = #state{ip = undefined}) ->
    {[<<"GET">>, <<"HEAD">>, <<"OPTIONS">>], Req, S};
allowed_methods(Req, S = #state{}) ->
    {[<<"GET">>, <<"HEAD">>, <<"OPTIONS">>, <<"PUT">>], Req, S}.

forbidden(Req, S = #state{ip = undefined}) ->
    {false, Req, S};
forbidden(Req, S = #state{ip = Ip}) ->
    {PeerIp, _PeerPort} = cowboy_req:peer(Req),
    Allowed = http_api:peer_allowed(Ip, PeerIp),
    if (not Allowed) ->
        lager:debug("denied status update request from ~p for host ~p", [PeerIp, Ip]);
    true -> ok end,
    {(not Allowed), Req, S#state{peer = PeerIp}}.

content_types_provided(Req, S = #state{}) ->
    Types = [
        {{<<"application">>, <<"json">>, '*'}, to_json}
    ],
    {Types, Req, S}.

resource_exists(Req, S = #state{ip = undefined}) ->
    {ok, Pools} = session_ra:get_pools_for(#{user => <<>>, groups => []}),
    case Pools of
        [#{id := Pool} | _] ->
            case session_ra:get_prefs(Pool, <<>>) of
                {ok, Ips} when length(Ips) > 0 ->
                    Metas = [begin {ok, Meta} = session_ra:get_host(Ip), Meta end
                        || Ip <- Ips],
                    {true, Req, S#state{meta = Metas}};
                _ ->
                    {false, Req, S}
            end;
        _ ->
            {false, Req, S}
    end;
resource_exists(Req, S = #state{ip = Ip}) ->
    case session_ra:get_host(Ip) of
        {ok, Meta} -> {true, Req, S#state{meta = Meta}};
        _ -> {false, Req, S}
    end.

content_types_accepted(Req, S = #state{}) ->
    Types = [
        {{<<"application">>, <<"json">>, '*'}, from_json}
    ],
    {Types, Req, S}.

to_json(Req, S = #state{ip = undefined, meta = Metas}) ->
    ReportTimes = [T || #{last_report := T} <- Metas],
    Now = erlang:system_time(second),
    LastReport = case ReportTimes of
        [] -> 0;
        _ -> lists:max(ReportTimes)
    end,
    Json = [
        {last_update, Now - LastReport},
        {count, length(Metas)}
    ],
    {jsx:encode(Json), Req, S};
to_json(Req, S = #state{meta = Meta}) ->
    Json = maps:filter(fun
        (ip, _) -> true;
        (hostname, _) -> true;
        (port, _) -> true;
        (enabled, _) -> true;
        (idle_from, _) -> true;
        (image, _) -> true;
        (role, _) -> true;
        (_, _) -> false
    end, Meta),
    {jsx:encode(Json), Req, S}.

from_json(Req, S = #state{ip = Ip, peer = Peer}) ->
    {ok, Json, Req2} = cowboy_req:read_body(Req),
    PeerBin = iolist_to_binary([inet:ntoa(Peer)]),
    Input = jsx:decode(Json, [return_maps, {labels, atom}]),
    Now = erlang:system_time(second),
    UpdateChanges0 = maps:filter(fun
        (image, _) -> true;
        (role, _) -> true;
        (_, _) -> false
    end, Input),
    UpdateChanges1 = case Input of
        #{sessions := Sessions = [_ | _]} ->
            case [Now - I || #{idle := I} <- Sessions] of
                [] -> UpdateChanges0;
                Idles -> UpdateChanges0#{idle_from => lists:max(Idles)}
            end;
        _ -> UpdateChanges0
    end,
    UpdateChanges2 = UpdateChanges1#{
        hypervisor => PeerBin,
        ip => Ip,
        port => 3389
    },
    {ok, IpInet} = inet:parse_address(binary_to_list(Ip)),
    UpdateChanges3 = case http_api:rev_lookup(IpInet) of
        {ok, HostnameStr} ->
            Hostname = iolist_to_binary([HostnameStr]),
            UpdateChanges2#{hostname => Hostname};
        _ ->
            UpdateChanges2
    end,
    {Status, LastTransition} = case session_ra:get_host(Ip) of
        {ok, Meta0} ->
            #{report_state := RS} = Meta0,
            {session_ra:update_host(UpdateChanges3), RS};
        {error, not_found} ->
            case session_ra:create_host(UpdateChanges3) of
                ok ->
                    ok = session_ra:enable_host(Ip),
                    {ok, Meta0} = session_ra:get_host(Ip),
                    #{report_state := RS} = Meta0,
                    {ok, RS};
                Other ->
                    Meta0 = #{},
                    {Other, {busy, 0}}
            end
    end,
    case Status of
        ok ->
            case Input of
                #{status := <<"available">>} ->
                    ok = session_ra:status_report(Ip, available);
                _ ->
                    ok = session_ra:status_report(Ip, busy)
            end,
            NewSessions = case {Input, Meta0} of
                {#{sessions := ISessions}, #{session_history := SHist}} ->
                    new_sessions(ISessions, LastTransition,
                        queue:to_list(SHist));
                _ -> []
            end,
            lists:foreach(fun (InpSess) ->
                #{'session-id' := IdI, start := StartI, user := UserI} = InpSess,
                TypeI = case InpSess of
                    #{type := T} -> T;
                    _ -> <<"other">>
                end,
                {StartI2, ReportTime} = case StartI of
                    0 -> {erlang:system_time(second), true};
                    _ -> {StartI, false}
                end,
                Sess = #{
                    time => StartI2,
                    report_time => ReportTime,
                    user => UserI,
                    type => TypeI,
                    id => IdI
                },
                ok = session_ra:add_session(Ip, Sess)
            end, NewSessions),
            {true, Req2, S};
        _ ->
            {false, Req2, S}
    end.

new_sessions(Inputs, LastTransition, PoolRecords) ->
    lists:sort(fun (InpA, InpB) ->
        #{start := StartA, user := UserA} = InpA,
        #{start := StartB, user := UserB} = InpB,
        if
            (StartA < StartB) -> true;
            (StartA > StartB) -> false;
            (UserA < UserB) -> true;
            (UserA > UserB) -> false;
            true -> false
        end
    end, lists:filter(fun (Inp) ->
        not (match_session(Inp, LastTransition, PoolRecords))
    end, Inputs)).

match_session(_, _, []) -> false;
match_session(#{start := 0, user := UserI}, {St, TB}, PoolRecords) ->
    PRsWithRepTime = lists:filter(fun
        (#{report_time := true}) -> true;
        (_) -> false
    end, PoolRecords),
    case lists:last(PRsWithRepTime) of
        #{user := UserI} when (St =:= busy) -> true;
        #{user := UserI, time := T} when (St =:= available) and (TB < T) -> true;
        _ -> false
    end;
match_session(Input, LT, [PoolRecord | Rest]) ->
    #{start := StartI, user := UserI} = Input,
    TypeI = case Input of
        #{type := T} -> T;
        _ -> <<"other">>
    end,
    #{time := StartP, user := UserP, type := TypeP} = PoolRecord,
    MaxDelta = case PoolRecord of
        #{report_time := true} -> 600;
        _ -> 30
    end,
    if
        not (UserP =:= UserI) -> match_session(Input, LT, Rest);
        not (TypeI =:= TypeP) -> match_session(Input, LT, Rest);
        (abs(StartP - StartI) > MaxDelta) -> match_session(Input, LT, Rest);
        true -> true
    end.
