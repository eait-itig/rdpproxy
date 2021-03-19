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

-module(frontend).
-behaviour(rdp_server).

-include_lib("rdp_proto/include/rdp_server.hrl").

-export([
    init/1,
    init/2,
    handle_connect/4,
    init_ui/2,
    handle_event/3,
    handle_raw_data/3,
    terminate/2
    ]).

-export([register_metrics/0]).

register_metrics() ->
    prometheus_counter:new([
        {name, rdp_frontend_connections_total},
        {labels, [listener]},
        {help, "Total RDP connections accepted"}]),
    prometheus_counter:new([
        {name, rdp_frontend_connections_forwarded},
        {labels, [listener]},
        {help, "Total connections forwarded to a backend"}]),
    prometheus_histogram:new([
        {name, rdp_frontend_connection_duration_seconds},
        {labels, [listener]},
        {buckets, [2, 10, 60, 240, 900, 1800, 3600, 7200, 86400]},
        {duration_unit, false},
        {help, "Duration of frontend RDP connections"}]),
    ok.

-record(?MODULE, {
    peer :: term(),
    listener :: atom(),
    session :: session_ra:handle_state() | undefined,
    subs = [] :: [pid()],
    backend :: pid() | undefined,
    intercept = true :: boolean(),
    matched_sessid = false :: boolean(),
    connid :: binary() | undefined,
    t0 :: integer()
    }).

init(Peer) ->
    T0 = erlang:system_time(second),
    prometheus_counter:inc(rdp_frontend_connections_total, [default]),
    {ok, #?MODULE{peer = Peer, t0 = T0, listener = default}}.
init(Peer, Listener) ->
    prometheus_counter:inc(rdp_frontend_connections_total, [Listener]),
    T0 = erlang:system_time(second),
    {ok, #?MODULE{peer = Peer, t0 = T0, listener = Listener}}.

retry_start_backend(0, _, _, _, _, LastErr) -> LastErr;
retry_start_backend(N, Srv, L, HostBin, Port, _) ->
    case backend:start_link(Srv, L, HostBin, Port) of
        {ok, Backend} ->
            {ok, Backend};
        Err ->
            timer:sleep(200),
            retry_start_backend(N - 1, Srv, L, HostBin, Port, Err)
    end.
retry_start_backend(Srv, L, HostBin, Port) ->
    retry_start_backend(2, Srv, L, HostBin, Port, none).

handle_connect(Cookie, Protocols, Srv, S = #?MODULE{peer = P, listener = L}) ->
    lager:debug("connect ~p to listener ~p, protocols ~p", [P, L, Protocols]),
    % HostBin = <<"130.102.79.25">>,
    % User = <<"test">>,
    % Port = 3389,
    % Sess = #{ip => <<"130.102.79.25">>, port => 3389, user => <<"test">>},
    case session_ra:claim_handle(Cookie) of
       {ok, Sess = #{ip := HostBin, port := Port, user := User}} ->
            {PeerIp, PeerPort} = P,
            PeerStr = iolist_to_binary(inet:ntoa(PeerIp)),
            lager:debug("~p:~p: presented cookie ~p (~p), forwarding to ~p",
                [PeerStr, PeerPort, Cookie, User, HostBin]),
            prometheus_counter:inc(rdp_frontend_connections_forwarded, [L]),
            {ok, ConnId} = conn_ra:register_conn(S#?MODULE.peer, Sess),
            {ok, Backend} = retry_start_backend(Srv, L, binary_to_list(HostBin), Port),
            ok = rdp_server:watch_child(Srv, Backend),
            {accept_raw, S#?MODULE{session = Sess, backend = Backend, connid = ConnId}};

        _ ->
            {ok, ConnId} = conn_ra:register_conn(S#?MODULE.peer,
                #{ip => undefined, user => <<"_">>}),
            SslOpts = rdpproxy:config([frontend, L, ssl_options], [
                {certfile, "etc/cert.pem"},
                {keyfile, "etc/key.pem"}]),
            {accept, SslOpts, S#?MODULE{connid = ConnId}}
    end.

init_ui(Srv, S = #?MODULE{subs = [], listener = L, connid = ConnId}) ->
    {ok, Ui} = ui_fsm_sup:start_ui(Srv, L),
    lager:debug("frontend spawned ui_fsm ~p", [Ui]),
    Tsuds = rdp_server:get_tsuds(Srv),
    Caps = rdp_server:get_caps(Srv),
    conn_ra:annotate(ConnId, #{tsuds => Tsuds, ts_caps => Caps, ui_fsm => Ui}),
    {ok, S}.

handle_event({subscribe, Pid}, _Srv, S = #?MODULE{subs = Subs}) ->
    {ok, S#?MODULE{subs = [Pid | Subs]}};

handle_event(Event, Srv, S = #?MODULE{subs = Subs}) ->
    lists:foreach(fun(Sub) ->
        gen_fsm:send_event(Sub, {input, Srv, Event})
    end, Subs),
    {ok, S}.

handle_raw_data(Data, _Srv, S = #?MODULE{intercept = false, backend = B}) ->
    gen_fsm:send_event(B, {frontend_data, Data}),
    {ok, S};
handle_raw_data(Bin, _Srv,
            S = #?MODULE{intercept = true, backend = B, connid = ConnId}) ->
    %debug_print_data(Bin),
    case rdpp:decode_server(Bin) of
        %
        % Certain clients (like FreeRDP) with GFX enabled will learn during
        % the login screen session that 32bpp colour isn't supported. They will
        % then try to ask the backend server here for GFX/H264 without 32bpp
        % colour, which causes a reject from the MS RDP server.
        %
        % If we see someone trying GFX but without 32bpp colour, add it back
        % into their TSUDs.
        %
        {ok, {mcs_pdu, McsCi = #mcs_ci{}}, Rem} ->
            {ok, Tsuds0} = tsud:decode(McsCi#mcs_ci.data),

            conn_ra:annotate(S#?MODULE.connid, #{tsuds => Tsuds0}),

            TsudCore0 = lists:keyfind(tsud_core, 1, Tsuds0),
            Colors0 = TsudCore0#tsud_core.colors,
            Caps0 = TsudCore0#tsud_core.capabilities,

            TsudCluster0 = lists:keyfind(tsud_cluster, 1, Tsuds0),
            #?MODULE{session = #{sessid := SessId}} = S,
            #tsud_cluster{sessionid = TheirSessId} = TsudCluster0,

            MatchesSessId = (SessId == TheirSessId),
            S1 = case MatchesSessId of
                false ->
                    lager:warning("sessid mismatch (ours = ~p, they sent = ~p), "
                        "will not rewrite ts_info (no auto-login)",
                        [SessId, TheirSessId]),
                    conn_ra:annotate(ConnId, #{forwarded_creds => false}),
                    S#?MODULE{matched_sessid = false};
                true ->
                    conn_ra:annotate(ConnId, #{forwarded_creds => true}),
                    S#?MODULE{matched_sessid = true}
            end,

            HasGfx = lists:member(dynvc_gfx, Caps0),
            Has32Bpp = lists:member('32bpp', Colors0),

            lager:debug("core tsud: ~s", [tsud:pretty_print(TsudCore0)]),
            lager:debug("cluster tsud: ~s", [tsud:pretty_print(TsudCluster0)]),

            case {HasGfx, Has32Bpp} of
                {true, false} ->
                    % Remove the redirection info while we're here.
                    TsudCluster1 = TsudCluster0#tsud_cluster{sessionid = none},
                    lager:debug("rewriting client tsud: ~s", [tsud:pretty_print(TsudCluster1)]),
                    Tsuds1 = lists:keyreplace(tsud_cluster, 1, Tsuds0, TsudCluster1),

                    Colors1 = ['32bpp' | Colors0],
                    Color1 = '32bpp',
                    Caps1 = ['want_32bpp' | Caps0],
                    TsudCore1 = TsudCore0#tsud_core{colors = Colors1, color = Color1, capabilities = Caps1},
                    lager:debug("rewriting client tsud: ~s", [tsud:pretty_print(TsudCore1)]),
                    Tsuds2 = lists:keyreplace(tsud_core, 1, Tsuds1, TsudCore1),

                    TsudsBin1 = lists:foldl(fun(Tsud, SoFar) ->
                        {ok, TsudBin} = tsud:encode(Tsud),
                        <<SoFar/binary, TsudBin/binary>>
                    end, <<>>, Tsuds2),
                    {ok, OutCiData} = mcsgcc:encode_ci(McsCi#mcs_ci{data = TsudsBin1}),
                    {ok, OutDtData} = x224:encode(#x224_dt{data = OutCiData}),
                    {ok, OutPkt} = tpkt:encode(OutDtData),
                    gen_fsm:send_event(B, {frontend_data, <<OutPkt/binary, Rem/binary>>}),
                    {ok, S1};
                _ ->
                    gen_fsm:send_event(B, {frontend_data, Bin}),
                    {ok, S1}
            end;
        %
        % The last thing we have to rewrite before we can just be a data shovel
        % is the ts_info PDU. Here we'll forcibly inject the domain, username
        % and pw from the cookie.
        %
        {ok, {mcs_pdu, McsData = #mcs_data{data = RdpData0}}, Rem} ->
            case rdpp:decode_basic(RdpData0) of
                {ok, TsInfo0 = #ts_info{}} ->
                    conn_ra:annotate(S#?MODULE.connid, #{
                        ts_info => TsInfo0#ts_info{password = snip}
                    }),

                    #?MODULE{matched_sessid = MatchedSessId} = S,
                    #?MODULE{session = #{user := User,
                        password := Password, domain := Domain}} = S,
                    TsInfo1 = TsInfo0#ts_info{
                        flags = [autologon, unicode | TsInfo0#ts_info.flags]},
                    Unicode = lists:member(unicode, TsInfo1#ts_info.flags),
                    TsInfo2 = TsInfo1#ts_info{
                        domain = if
                            Unicode ->
                                unicode:characters_to_binary(
                                    <<Domain/binary,0>>, latin1, {utf16, little});
                            true ->
                                <<Domain/binary, 0>>
                            end,
                        username = if
                            Unicode and MatchedSessId ->
                                unicode:characters_to_binary(
                                    <<User/binary,0>>, utf8, {utf16, little});
                            MatchedSessId ->
                                <<User/binary, 0>>;
                            Unicode ->
                                <<0, 0>>;
                            true ->
                                <<0>>
                            end,
                        password = if
                            Unicode and MatchedSessId ->
                                unicode:characters_to_binary(
                                    <<Password/binary,0>>, utf8, {utf16, little});
                            MatchedSessId ->
                                <<Password/binary, 0>>;
                            Unicode ->
                                <<0, 0>>;
                            true ->
                                <<0>>
                            end
                        },
                    lager:debug("rewriting ts_info: ~s", [rdpp:pretty_print(TsInfo2#ts_info{password = snip, extra = snip})]),
                    {ok, RdpData1} = rdpp:encode_basic(TsInfo2),
                    {ok, McsOutBin} = mcsgcc:encode_dpdu(McsData#mcs_data{data = RdpData1}),
                    {ok, X224OutBin} = x224:encode(#x224_dt{data = McsOutBin}),
                    {ok, OutBin} = tpkt:encode(X224OutBin),
                    gen_fsm:send_event(B, {frontend_data, <<OutBin/binary, Rem/binary>>}),
                    {ok, S#?MODULE{intercept = false}};
                _ ->
                    gen_fsm:send_event(B, {frontend_data, Bin}),
                    {ok, S}
            end;

        _ ->
            gen_fsm:send_event(B, {frontend_data, Bin}),
            {ok, S}
    end.

debug_print_data(<<>>) -> ok;
debug_print_data(Bin) ->
    case rdpp:decode_server(Bin) of
        {ok, {fp_pdu, _Pdu}, Rem} ->
            %error_logger:info_report(["frontend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
            debug_print_data(Rem);
        {ok, {x224_pdu, Pdu}, Rem} ->
            lager:info("frontend rx x224: ~s", [x224:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu = #mcs_srv_data{data = RdpData, channel = _Chan}}, Rem} ->
            case rdpp:decode_basic(RdpData) of
                {ok, Rec} ->
                    {ok, RdpData} = rdpp:encode_basic(Rec),
                    lager:info("frontend rx rdp_basic: ~s", [rdpp:pretty_print(Rec)]);
                _ ->
                    case rdpp:decode_sharecontrol(RdpData) of
                        {ok, #ts_demand{} = Rec} ->
                            case rdpp:encode_sharecontrol(Rec) of
                                {ok, RdpData} -> ok;
                                {ok, OtherData} ->
                                    file:write_file("backend_orig", RdpData),
                                    file:write_file("backend_reenc", OtherData),
                                    lager:info("original data = ~p, reenc data = ~p", [RdpData, OtherData]);
                                _ -> error(fail_reencode)
                            end,
                            lager:info("frontend rx rdp_sharecontrol: ~s", [rdpp:pretty_print(Rec)]);
                        {ok, Rec} ->
                            lager:info("frontend rx rdp_sharecontrol: ~s", [rdpp:pretty_print(Rec)]);
                        _ ->
                            lager:info("frontend rx mcs: ~s", [mcsgcc:pretty_print(Pdu)])
                    end
            end,
            debug_print_data(Rem);
        {ok, {mcs_pdu, McsCi = #mcs_ci{}}, Rem} ->
            {ok, Tsuds} = tsud:decode(McsCi#mcs_ci.data),
            lager:info("frontend rx ci with tsuds: ~s", [tsud:pretty_print(Tsuds)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, McsCr = #mcs_cr{}}, Rem} ->
            {ok, Tsuds} = tsud:decode(McsCr#mcs_cr.data),
            lager:info("frontend rx cr with tsuds: ~s", [tsud:pretty_print(Tsuds)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, #mcs_tir{}}, Rem} ->
            {ok, Data, _} = tpkt:decode(Bin),
            {ok, X224Pdu} = x224:decode(Data),
            lager:info("decode_cr: ~p, data: ~p", [mcsgcc:decode_cr(X224Pdu#x224_dt.data), Bin]),
            file:write_file("bad_cr", Bin),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu}, Rem} ->
            lager:info("frontend rx mcs: ~s", [mcsgcc:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, Something, Rem} ->
            lager:info("frontend unknown: ~p, rem = ~p", [Something, Rem]);
        {error, Reason} ->
            lager:info("frontend parse err: ~p", [Reason]),
            ok
    end.

terminate(_Reason, #?MODULE{listener = L, t0 = T0}) ->
    T1 = erlang:system_time(second),
    Dur = T1 - T0,
    prometheus_histogram:observe(rdp_frontend_connection_duration_seconds,
        [L], Dur),
    ok.
