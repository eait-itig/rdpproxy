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
    case pool_ra:get_prefs(new_user) of
        {ok, Ips} when length(Ips) > 0 ->
            Metas = [begin {ok, Meta} = pool_ra:get_host(Ip), Meta end
                || Ip <- Ips],
            {true, Req, S#state{meta = Metas}};
        _ ->
            {false, Req, S}
    end;
resource_exists(Req, S = #state{ip = Ip}) ->
    case pool_ra:get_host(Ip) of
        {ok, Meta} -> {true, Req, S#state{meta = Meta}};
        _ -> {false, Req, S}
    end.

content_types_accepted(Req, S = #state{}) ->
    Types = [
        {{<<"application">>, <<"json">>, '*'}, from_json}
    ],
    {Types, Req, S}.

to_json(Req, S = #state{ip = undefined, meta = Metas}) ->
    Json = [
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
        hypervisor => PeerBin
    },
    {ok, IpInet} = inet:parse_address(binary_to_list(Ip)),
    UpdateChanges3 = case http_api:rev_lookup(IpInet) of
        {ok, HostnameStr} ->
            Hostname = iolist_to_binary([HostnameStr]),
            UpdateChanges2#{hostname => Hostname};
        _ ->
            Hostname = Ip,
            UpdateChanges2
    end,
    case pool_ra:get_host(Ip) of
        {ok, Meta0} ->
            ok = pool_ra:update(Ip, UpdateChanges3);
        {error, not_found} ->
            ok = pool_ra:create(Ip, Hostname, 3389),
            ok = pool_ra:update(Ip, UpdateChanges3),
            ok = pool_ra:enable(Ip),
            {ok, Meta0} = pool_ra:get_host(Ip)
    end,
    case Input of
        #{status := <<"available">>} ->
            ok = pool_ra:status_report(Ip, available);
        _ ->
            ok = pool_ra:status_report(Ip, busy)
    end,
    NewSessions = case {Input, Meta0} of
        {#{sessions := ISessions}, #{session_history := SHist}} ->
            new_sessions(ISessions, queue:to_list(SHist));
        _ -> []
    end,
    lists:foreach(fun (InpSess) ->
        #{'session-id' := IdI, start := StartI, user := UserI} = InpSess,
        TypeI = case InpSess of
            #{type := T} -> T;
            _ -> <<"other">>
        end,
        Sess = #{
            time => StartI,
            user => UserI,
            type => TypeI,
            id => IdI
        },
        ok = pool_ra:add_session(Ip, Sess)
    end, NewSessions),
    {true, Req2, S}.

new_sessions(Inputs, PoolRecords) ->
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
        not lists:any(fun (PoolRec) ->
            match_session(Inp, PoolRec)
        end, PoolRecords)
    end, Inputs)).

match_session(Input, PoolRecord) ->
    #{'session-id' := IdI, start := StartI, user := UserI} = Input,
    TypeI = case Input of
        #{type := T} -> T;
        _ -> <<"other">>
    end,
    #{time := StartP, user := UserP, type := TypeP, id := IdP} = PoolRecord,
    if
        not (IdI =:= IdP) -> false;
        not (UserP =:= UserI) -> false;
        not (TypeI =:= TypeP) -> false;
        abs(StartP - StartI) > 5 -> false;
        true -> true
    end.
