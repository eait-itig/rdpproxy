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

-module(backend).
-behaviour(gen_fsm).

-include_lib("public_key/include/public_key.hrl").
-include_lib("rdp_proto/include/rdp_server.hrl").

-export([start_link/4, probe/2]).
-export([initiation/2, proxy_intercept/2, proxy_watch_demand/2,
    proxy_watch_logon/2, proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-export([register_metrics/0]).

% Keep last N small packets to search for disconnect reason
-define(END_PKT_BUF, 32).
-define(END_PKT_MAX_SZ, 128).

register_metrics() ->
    prometheus_counter:new([
        {name, rdp_backend_connections_total},
        {labels, [listener, peer]},
        {help, "Outgoing RDP connections made to backend machines"}]),
    prometheus_counter:new([
        {name, rdp_backend_probes_total},
        {help, "Probes issued to backends to check their status"}]),
    prometheus_counter:new([
        {name, rdp_backend_probe_errors_total},
        {help, "Errors while running backend:probe/2"}]),
    prometheus_counter:new([
        {name, rdp_backend_probe_errors_per_backend_total},
        {labels, [peer]},
        {help, "Errors while running backend:probe/2"}]),
    prometheus_histogram:new([
        {name, rdp_backend_probe_duration_milliseconds},
        {labels, [peer]},
        {buckets, [20, 50, 100, 500, 2000, 10000]},
        {duration_unit, false},
        {help, "Duration of backend RDP probes which returned success"}]),
    ok.

-spec start_link(Frontend :: pid(), Listener :: atom(), Address :: inet:ip_address() | inet:hostname(), Port :: inet:port_number()) -> {ok, pid()} | {error, any()}.
start_link(Frontend, L, Address, Port) ->
    gen_fsm:start_link(?MODULE, [Frontend, L, Address, Port], [{timeout, 10000}]).

probe(Address, Port) ->
    % Just use the first listener in the config
    prometheus_counter:inc(rdp_backend_probes_total, []),
    T0 = erlang:system_time(microsecond),
    [{L, _} | _] = rdpproxy:config(frontend, []),
    case (catch gen_fsm:start(?MODULE, [self(), L, Address, Port], [{timeout, 7000}])) of
        {ok, Pid} ->
            MonRef = monitor(process, Pid),
            probe_rx(Pid, Address, T0, MonRef, {error, bad_host});
        {'EXIT', Reason} -> {error, Reason};
        Err -> Err
    end.

probe_rx(Pid, Peer, T0, MonRef, RetVal) ->
    receive
        {backend_ready, Pid} ->
            T1 = erlang:system_time(microsecond),
            Delta = (T1 - T0) / 1000,
            prometheus_histogram:observe(
                rdp_backend_probe_duration_milliseconds, [Peer], Delta),
            gen_fsm:send_event(Pid, close),
            probe_rx(Pid, Peer, T0, MonRef, ok);
        {'DOWN', MonRef, process, Pid, E} when (E =:= no_ssl) or (E =:= bad_cert) ->
            prometheus_counter:inc(rdp_backend_probe_errors_per_backend_total,
                [Peer]),
            prometheus_counter:inc(rdp_backend_probe_errors_total),
            {error, E};
        {'DOWN', MonRef, process, Pid, Reason} ->
            prometheus_counter:inc(rdp_backend_probe_errors_per_backend_total,
                [Peer]),
            prometheus_counter:inc(rdp_backend_probe_errors_total),
            lager:debug("probe backend ~p down: ~p", [Pid, Reason]),
            RetVal
    after 10000 ->
        exit(Pid, kill),
        probe_rx(Pid, Peer, T0, MonRef, {error, timeout})
    end.

-record(?MODULE, {
    addr :: inet:ip_address() | inet:hostname(),
    port :: integer(),
    sock :: gen_tcp:socket(),
    listener :: atom(),
    sslsock=none :: none | ssl:ssl_socket(),
    themref=0 :: integer(),
    usref=0 :: integer(),
    pktq :: queue:queue(binary()) | undefined,
    server :: rdp_server:server() | pid(),
    origcr :: #x224_cr{},
    sharechan :: undefined | integer(),
    logon = false :: boolean(),
    t0 :: integer(),
    connid :: undefined | binary()
    }).

%% @private
init([Pid, L, Address, Port]) when is_pid(Pid) ->
    init([Pid, L, Address, Port, #x224_cr{
        class = 0, dst = 0, src = crypto:rand_uniform(2000,9999),
        rdp_protocols = [ssl]
        }]);

init([Srv = {P, _}, L, Address, Port]) when is_pid(P) ->
    #x224_state{cr = OrigCr} = rdp_server:x224_state(Srv),
    init([Srv, L, Address, Port, OrigCr]);

init([Srv, L, Address, Port, OrigCr]) ->
    random:seed(os:timestamp()),
    prometheus_counter:inc(rdp_backend_connections_total, [L, Address]),
    #x224_cr{src = Us} = OrigCr,
    lager:debug("backend for frontend ~p", [Srv]),
    case gen_tcp:connect(Address, Port, [binary, {active, once}, {nodelay, true}, {keepalive, true}], 5000) of
        {ok, Sock} ->
            lager:debug("backend connected to ~p", [Address]),
            Cr = OrigCr#x224_cr{rdp_protocols = [ssl], rdp_cookie = none},
            {ok, CrData} = x224:encode(Cr),
            {ok, Packet} = tpkt:encode(CrData),
            ok = gen_tcp:send(Sock, Packet),
            T0 = erlang:system_time(millisecond),
            {ok, initiation, #?MODULE{
                addr = Address, port = Port, server = Srv, listener = L,
                sock = Sock, usref = Us, origcr = OrigCr, t0 = T0,
                pktq = queue:new()}};

        {error, Reason} ->
            case Srv of
                P when is_pid(P) -> ok;
                {P, _} when is_pid(P) ->
                    session_ra:host_error(iolist_to_binary([Address]), Reason)
            end,
            {stop, Reason}
    end.

initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = error, rdp_error = ssl_not_allowed}},
        #?MODULE{addr = Address, usref = UsRef, server = Srv} = Data) ->
    case Srv of
        P when is_pid(P) -> ok;
        {P, _} when is_pid(P) ->
            session_ra:host_error(iolist_to_binary([Address]), no_ssl)
    end,
    {stop, no_ssl, Data};

initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = ok} = Pkt}, #?MODULE{usref = UsRef, sock = Sock, server = Srv, addr = Address, listener = L} = Data) ->
    #x224_cc{src = ThemRef, rdp_selected = Selected} = Pkt,

    HasSsl = lists:member(ssl, Selected),

    if HasSsl ->
        inet:setopts(Sock, [{packet, raw}]),
        Opts0 = rdpproxy:config([backend, ssl_options], [{verify, verify_none}]),
        Opts1 = case session_ra:get_host(iolist_to_binary([Address])) of
            {ok, #{hostname := Name}} ->
                [{server_name_indication,
                  binary_to_list(iolist_to_binary([Name]))} | Opts0];
            _ ->
                Opts0
        end,
        lager:debug("ssl opts = ~p", [Opts1]),
        case ssl:connect(Sock, Opts1) of
            {ok, SslSock} ->
                ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),

                {ok, Cert} = ssl:peercert(SslSock),
                #'OTPCertificate'{
                    tbsCertificate = #'OTPTBSCertificate'{
                        subject = Subj, issuer = Issuer}
                } = public_key:pkix_decode_cert(Cert, otp),
                lager:debug("~p: cert subject = ~p, issuer = ~p",
                    [Address, Subj, Issuer]),

                case Srv of
                    P when is_pid(P) ->
                        P ! {backend_ready, self()};
                    {P,_} when is_pid(P) ->
                        rdp_server:start_tls(Srv,
                            rdpproxy:config([frontend, L, ssl_options], [
                                {certfile, "etc/cert.pem"},
                                {keyfile, "etc/key.pem"}]), Pkt)
                end,

                Data1 = Data#?MODULE{sslsock = SslSock, themref = ThemRef},

                Data2 = case conn_ra:pid_to_conn_id(P) of
                    {ok, ConnId} -> Data1#?MODULE{connid = ConnId};
                    _ -> Data1
                end,

                {next_state, proxy_intercept, Data2};

            {error, {tls_alert, {bad_certificate, Why}}} ->
                lager:debug("bad TLS certificate: ~p", [Why]),
                gen_tcp:close(Sock),
                case Srv of
                    P when is_pid(P) -> ok;
                    {P, _} when is_pid(P) ->
                        session_ra:host_error(iolist_to_binary([Address]), bad_cert)
                end,
                {stop, bad_cert, Data};

            {error, {tls_alert, {handshake_failure, Why}}} ->
                lager:debug("tls handshake failure: ~p", [Why]),
                ErrCode = case string:find(Why, "bad_cert") of
                    nomatch -> tls_handshake_error;
                    _ -> bad_cert
                end,
                gen_tcp:close(Sock),
                case Srv of
                    P when is_pid(P) -> ok;
                    {P, _} when is_pid(P) ->
                        session_ra:host_error(iolist_to_binary([Address]), ErrCode)
                end,
                {stop, ErrCode, Data};

            {error, Err} ->
                lager:debug("tls connect failure: ~p", [Err]),
                gen_tcp:close(Sock),
                case Srv of
                    P when is_pid(P) -> ok;
                    {P, _} when is_pid(P) ->
                        session_ra:host_error(iolist_to_binary([Address]), tls_error)
                end,
                {stop, tls_error, Data}
        end;

    true ->
        lager:debug("upstream server rejected SSL, dying"),
        gen_tcp:close(Sock),
        case Srv of
            P when is_pid(P) -> ok;
            {P, _} when is_pid(P) ->
                session_ra:host_error(iolist_to_binary([Address]), no_ssl)
        end,
        {stop, no_ssl, Data}
    end;

initiation({pdu, #x224_cc{class = 0, dst = Ref} = Pkt}, #?MODULE{} = Data) ->
    lager:debug("upstream sent x224 cc with dst = ~p, changing our ref",
        [Ref]),
    Data1 = Data#?MODULE{usref = Ref},
    initiation({pdu, Pkt}, Data1).

proxy_intercept({data, Bin}, #?MODULE{server = Srv, origcr = OrigCr} = Data) ->
    case rdpp:decode_connseq(Bin) of
        %
        % The server sends a copy of what protocols the client requested in the
        % x224_cr in its svr_core TSUD. Fish this out and rewrite it to what our
        % real client said to us (probably has credssp as well as ssl). If it
        % doesn't match, the client will disconnect.
        %
        {ok, {mcs_pdu, Cr = #mcs_cr{data = TsudsBin0}}, Rem} ->
            {ok, Tsuds0} = tsud:decode(TsudsBin0),
            TsudSvrCore0 = lists:keyfind(tsud_svr_core, 1, Tsuds0),
            TsudSvrCore1 = TsudSvrCore0#tsud_svr_core{requested = OrigCr#x224_cr.rdp_protocols},
            lager:debug("rewriting tsud: ~p", [TsudSvrCore1]),
            Tsuds1 = lists:keyreplace(tsud_svr_core, 1, Tsuds0, TsudSvrCore1),
            TsudsBin1 = lists:foldl(fun(Tsud, SoFar) ->
                {ok, TsudBin} = tsud:encode(Tsud),
                <<SoFar/binary, TsudBin/binary>>
            end, <<>>, Tsuds1),
            {ok, OutCrData} = mcsgcc:encode_cr(Cr#mcs_cr{data = TsudsBin1}),
            {ok, OutDtData} = x224:encode(#x224_dt{data = OutCrData}),
            {ok, OutPkt} = tpkt:encode(OutDtData),
            rdp_server:send_raw(Srv, <<OutPkt/binary, Rem/binary>>),
            {next_state, proxy_watch_demand, Data};
        _ ->
            rdp_server:send_raw(Srv, Bin),
            {next_state, proxy_intercept, Data}
    end;

proxy_intercept({frontend_data, Bin}, #?MODULE{sock = Sock, sslsock = SslSock} = Data) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy_intercept, Data};

proxy_intercept(close, D = #?MODULE{}) ->
    {stop, normal, D}.

proxy_watch_demand({data, Bin}, #?MODULE{server = Srv} = Data0) ->
    case (catch rdpp:decode_client(Bin)) of
        {ok, {mcs_pdu, #mcs_srv_data{data = RdpData, channel = Chan}}, _} ->
            case (catch rdpp:decode_sharecontrol(RdpData)) of
                {ok, #ts_demand{sourcedesc = <<"RDP",0>>}} ->
                    lager:debug("backend sent ts_demand, share channel = ~p",
                        [Chan]),
                    Data1 = Data0#?MODULE{sharechan = Chan},
                    rdp_server:send_raw(Srv, Bin),
                    {next_state, proxy_watch_logon, Data1};
                {ok, #ts_sharedata{data = #ts_set_error_info{info = E}}} ->
                    {FPid, _} = Srv,
                    lager:debug("backend error: ~p", [E]),
                    #?MODULE{addr = Address} = Data0,
                    session_ra:host_error(iolist_to_binary([Address]), E),
                    conn_ra:annotate(FPid, #{ts_error_info => E}),
                    rdp_server:send_raw(Srv, Bin),
                    {next_state, proxy_watch_demand, Data0};
                _ ->
                    rdp_server:send_raw(Srv, Bin),
                    {next_state, proxy_watch_demand, Data0}
            end;
        _ ->
            rdp_server:send_raw(Srv, Bin),
            {next_state, proxy_watch_demand, Data0}
    end;

proxy_watch_demand({frontend_data, Bin}, #?MODULE{sock = Sock, sslsock = SslSock} = Data) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy_watch_demand, Data};

proxy_watch_demand(close, D = #?MODULE{}) ->
    {stop, normal, D}.

proxy_watch_logon({data, Bin}, #?MODULE{server = Srv, sharechan = Chan, t0 = T0} = Data) ->
    T1 = erlang:system_time(millisecond),
    Delta = T1 - T0,
    % If it's been 5 minutes and there hasn't been a logon event, stop parsing
    % the traffic (probably the client disabled it or it was an auto-reconnect)
    ReturnState = if
        (Delta > 300000) -> proxy;
        true -> proxy_watch_logon
    end,
    case (catch rdpp:decode_client(Bin)) of
        {ok, {mcs_pdu, #mcs_srv_data{data = RdpData, channel = Chan}}, _} ->
            case (catch rdpp:decode_sharecontrol(RdpData)) of
                {ok, #ts_sharedata{data = #ts_session_info_error{status = Status}}} ->
                    {FPid, _} = Srv,
                    lager:debug("backend session status: ~p", [Status]),
                    conn_ra:annotate(FPid, #{ts_session_status => Status}),
                    rdp_server:send_raw(Srv, Bin),
                    {next_state, ReturnState, Data};
                {ok, #ts_sharedata{data = #ts_session_info_logon{sessionid = N}}} ->
                    {FPid, _} = Srv,
                    lager:debug("backend session id: ~p", [N]),
                    conn_ra:annotate(FPid, #{ts_session_id => N}),
                    rdp_server:send_raw(Srv, Bin),
                    {next_state, proxy, Data#?MODULE{logon = true}};
                {ok, #ts_sharedata{data = #ts_set_error_info{info = E}}} ->
                    {FPid, _} = Srv,
                    lager:debug("backend error info: ~p", [E]),
                    IsError = case E of
                        {logoff, _} -> false;
                        {disconnect, _} -> false;
                        no_error -> false;
                        _ -> true
                    end,
                    Data1 = if
                        IsError ->
                            #?MODULE{addr = Address} = Data,
                            session_ra:host_error(
                                iolist_to_binary([Address]), E),
                            Data;

                        not IsError ->
                            Data#?MODULE{logon = true}
                    end,
                    conn_ra:annotate(FPid, #{ts_error_info => E}),
                    rdp_server:send_raw(Srv, Bin),
                    {next_state, ReturnState, Data1};
                _ ->
                    rdp_server:send_raw(Srv, Bin),
                    {next_state, ReturnState, Data}
            end;
        _ ->
            rdp_server:send_raw(Srv, Bin),
            {next_state, ReturnState, Data}
    end;

proxy_watch_logon({frontend_data, Bin}, #?MODULE{sock = Sock, sslsock = SslSock} = Data) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy_watch_logon, Data};

proxy_watch_logon(close, D = #?MODULE{}) ->
    {stop, normal, D}.

proxy({data, Bin}, #?MODULE{server = Srv, pktq = undefined} = Data) ->
    rdp_server:send_raw(Srv, Bin),
    {next_state, proxy, Data};

proxy({data, Bin}, #?MODULE{server = Srv} = Data) when byte_size(Bin) > ?END_PKT_MAX_SZ ->
    rdp_server:send_raw(Srv, Bin),
    {next_state, proxy, Data};

proxy({data, Bin}, #?MODULE{server = Srv, pktq = Q0} = Data0) ->
    rdp_server:send_raw(Srv, Bin),
    Q1 = queue:in(Bin, Q0),
    Q2 = case queue:len(Q1) of
        N when N > ?END_PKT_BUF ->
            {{value, _}, QQ} = queue:out(Q1),
            QQ;
        _ ->
            Q1
    end,
    Data1 = Data0#?MODULE{pktq = Q2},
    {next_state, proxy, Data1};


proxy({frontend_data, Bin}, #?MODULE{sock = Sock, sslsock = SslSock, pktq = undefined} = Data) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy, Data};

proxy({frontend_data, Bin}, #?MODULE{sock = Sock, sslsock = SslSock} = Data) when byte_size(Bin) > ?END_PKT_MAX_SZ ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy, Data};

proxy({frontend_data, Bin}, #?MODULE{sock = Sock, sslsock = SslSock, pktq = Q0} = Data0) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    Q1 = queue:in(Bin, Q0),
    Q2 = case queue:len(Q1) of
        N when N > ?END_PKT_BUF ->
            {{value, _}, QQ} = queue:out(Q1),
            QQ;
        _ ->
            Q1
    end,
    Data1 = Data0#?MODULE{pktq = Q2},
    {next_state, proxy, Data1};

proxy(close, D = #?MODULE{}) ->
    {stop, normal, D}.

debug_print_data(<<>>) -> ok;
debug_print_data(Bin) ->
    case rdpp:decode_client(Bin) of
        {ok, {fp_pdu, Pdu}, Rem} ->
            lager:info("backend rx fastpath: ~s", [fastpath:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, {x224_pdu, Pdu}, Rem} ->
            lager:info("backend rx x224: ~s", [x224:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu = #mcs_srv_data{data = RdpData}}, Rem} ->
            case rdpp:decode_basic(RdpData) of
                {ok, Rec} ->
                    case rdpp:encode_basic(Rec) of
                        {ok, RdpData} ->
                            lager:info("backend rx rdp_basic: ~s", [rdpp:pretty_print(Rec)]);
                        {ok, _OtherData} ->
                            lager:info("backend rx rdp_basic (NOT MATCH): ~s", [rdpp:pretty_print(Rec)])
                    end;
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
                            lager:info("backend rx rdp_sharecontrol: ~s", [rdpp:pretty_print(Rec)]);
                        {ok, Rec} ->
                            lager:info("backend rx rdp_sharecontrol: ~s", [rdpp:pretty_print(Rec)]);
                        Err ->
                            lager:info("backend sharecontrol decode: ~p", [Err]),
                            lager:info("backend rx mcsdata: ~s", [mcsgcc:pretty_print(Pdu)])
                    end
            end,
            debug_print_data(Rem);
        {ok, {mcs_pdu, McsCr = #mcs_cr{}}, Rem} ->
            {ok, Tsuds} = tsud:decode(McsCr#mcs_cr.data),
            lager:info("backend rx cr with tsuds: ~s", [tsud:pretty_print(Tsuds)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, #mcs_tir{}}, Rem} ->
            {ok, Data, _} = tpkt:decode(Bin),
            {ok, X224Pdu} = x224:decode(Data),
            lager:info("decode_cr: ~p, data: ~p", [mcsgcc:decode_cr(X224Pdu#x224_dt.data), Bin]),
            file:write_file("bad_cr", Bin),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu}, Rem} ->
            lager:info("backend rx mcs: ~s", [mcsgcc:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, Something, Rem} ->
            lager:info("backend unknown: ~p, rem = ~p", [Something, Rem]);
        {error, Reason} ->
            lager:info("backend parse err: ~p", [Reason]),
            ok
    end.

%% @private
handle_info({tcp, Sock, Bin}, State, #?MODULE{sslsock = SslSock, sock = Sock} = Data) ->
    %debug_print_data(Bin),
    case rdpp:decode_connseq(Bin) of
        {ok, {x224_pdu, Pdu}, Rem} ->
            case byte_size(Rem) of
                N when N > 0 -> self() ! {ssl, SslSock, Rem};
                _ -> ok
            end,
            ?MODULE:State({pdu, Pdu}, Data);
        Other ->
            lager:info("backend_out: ~p", [Other]),
            {next_state, State, Data}
    end;

handle_info({ssl, SslSock, Bin}, State, #?MODULE{sslsock = SslSock} = Data)
        when (State =:= proxy) orelse (State =:= proxy_intercept) orelse
             (State =:= proxy_watch_demand) orelse (State =:= proxy_watch_logon) ->
    %debug_print_data(Bin),
    ?MODULE:State({data, Bin}, Data);
handle_info({ssl, SslSock, Bin}, State, #?MODULE{sock = Sock, sslsock = SslSock} = Data) ->
    handle_info({tcp, Sock, Bin}, State, Data);

handle_info({ssl_closed, SslSock}, State, #?MODULE{sslsock = SslSock} = Data) ->
    ?MODULE:State(close, Data);

handle_info({ssl_error, SslSock, Why}, State, #?MODULE{sslsock = SslSock} = Data) ->
    lager:debug("backend ssl error in state ~p: ~p", [State, Why]),
    ssl:close(SslSock),
    {stop, normal, Data};

handle_info({tcp_closed, Sock}, State, #?MODULE{sock = Sock} = Data) ->
    ?MODULE:State(close, Data);

handle_info({tcp_error, Sock, Why}, State, #?MODULE{sock = Sock} = Data) ->
    lager:debug("backend tcp error in state ~p: ~p", [State, Why]),
    gen_tcp:close(Sock),
    {stop, normal, Data};

handle_info(Msg, State, Data) ->
    lager:info("got ~p", [Msg]),
    {next_state, State, Data}.

check_pkt_errors([], #?MODULE{}) -> [];
check_pkt_errors([<<>> | Rest], D = #?MODULE{}) ->
    check_pkt_errors(Rest, D);
check_pkt_errors([Bin | Rest], D = #?MODULE{sharechan = Chan, addr = Address}) ->
    case (catch rdpp:decode_connseq(Bin)) of
        {ok, {mcs_pdu, #mcs_srv_data{data = RdpData, channel = Chan}}, Rem} ->
            case (catch rdpp:decode_sharecontrol(RdpData)) of
                {ok, #ts_sharedata{data = #ts_shutdown{}}} ->
                    #?MODULE{connid = ConnId} = D,
                    lager:debug("backend ts_shutdown (~Bb)", [byte_size(Bin)]),
                    conn_ra:annotate(ConnId, #{ts_error_info => {logoff, client}}),
                    [no_error | check_pkt_errors([Rem | Rest], D)];
                {ok, #ts_sharedata{data = #ts_shutdown_denied{}}} ->
                    #?MODULE{connid = ConnId} = D,
                    lager:debug("backend ts_shutdown_denied (~Bb)", [byte_size(Bin)]),
                    conn_ra:annotate(ConnId, #{ts_error_info => {disconnect, client}}),
                    [no_error | check_pkt_errors([Rem | Rest], D)];
                {ok, #ts_sharedata{data = #ts_set_error_info{info = E}}} ->
                    #?MODULE{connid = ConnId} = D,
                    lager:debug("backend error info: ~p (~Bb)", [E, byte_size(Bin)]),
                    conn_ra:annotate(ConnId, #{ts_error_info => E}),
                    IsError = case E of
                        {logoff, _} -> false;
                        {disconnect, _} -> false;
                        no_error -> false;
                        _ -> true
                    end,
                    if
                        IsError ->
                            session_ra:host_error(
                                iolist_to_binary([Address]), E),
                            [error | check_pkt_errors([Rem | Rest], D)];
                        not IsError ->
                            [no_error | check_pkt_errors([Rem | Rest], D)]
                    end;
                {ok, #ts_sharedata{data = Rec}} ->
                    [{sharedata, element(1,Rec)} | check_pkt_errors([Rem | Rest], D)];
                {ok, Rec} ->
                    [element(1,Rec) | check_pkt_errors([Rem | Rest], D)];
                _ ->
                    [unknown | check_pkt_errors([Rem | Rest], D)]
            end;
        {ok, {mcs_pdu, #mcs_srv_data{channel = OtherChan}}, Rem} ->
            [{other_chan, OtherChan} | check_pkt_errors([Rem | Rest], D)];
        {ok, {mcs_pdu, #mcs_dpu{reason = Reason}}, Rem} ->
            lager:debug("backend mcs_dpu: ~p (~Bb)", [Reason, byte_size(Bin)]),
            ToAdd = case Reason of
                'rn-user-requested' -> no_error;
                'rn-provider-initiated' -> mo_error;
                _ -> {mcs_dpu, Reason}
            end,
            [ToAdd | check_pkt_errors([Rem | Rest], D)];
        {ok, {Type, _}, Rem} ->
            [Type | check_pkt_errors([Rem | Rest], D)];
        _ ->
            [unknown | check_pkt_errors(Rest, D)]
    end.

check_pktq_errors(#?MODULE{pktq = undefined}) ->
    lager:debug("backend closed, no pktq"),
    unknown;
check_pktq_errors(D = #?MODULE{pktq = Q}) ->
    Results = check_pkt_errors(queue:to_list(Q), D),
    lager:debug("backend closed with ~B on pktq: ~p",
        [queue:len(Q), lists:usort(Results)]),
    case lists:member(error, Results) of
        true ->
            error;
        _ ->
            case lists:member(no_error, Results) of
                true -> ok;
                _ -> unknown
            end
    end.

%% @private
terminate(Reason, proxy_watch_demand, D = #?MODULE{addr = Address}) ->
    lager:debug("backend conn closed without a ts_demand"),
    session_ra:host_error(iolist_to_binary([Address]), no_ts_demand),
    terminate(Reason, other, D);
terminate(Reason, proxy_watch_logon, D = #?MODULE{addr = Address, logon = false, t0 = T0}) ->
    lager:debug("backend conn closed without a good logon"),
    T1 = erlang:system_time(millisecond),
    Delta = T1 - T0,
    if
        (Delta > 3000) andalso (Delta < 300000) ->
            session_ra:host_error(iolist_to_binary([Address]), no_logon);
        true ->
            ok
    end,
    terminate(Reason, other, D);
terminate(Reason, proxy, D = #?MODULE{addr = Address, logon = false, t0 = T0}) ->
    case check_pktq_errors(D) of
        ok ->
            terminate(Reason, other, D);
        error ->
            terminate(Reason, other, D);
        unknown ->
            lager:debug("backend conn closed without a good logon"),
            T1 = erlang:system_time(millisecond),
            Delta = T1 - T0,
            if
                (Delta > 3000) andalso (Delta < 300000) ->
                    session_ra:host_error(iolist_to_binary([Address]),
                        no_logon);
                true ->
                    ok
            end,
            session_ra:host_error(iolist_to_binary([Address]), no_logon),
            terminate(Reason, other, D)
    end;
terminate(Reason, proxy, D = #?MODULE{logon = true}) ->
    check_pktq_errors(D),
    terminate(Reason, other, D);
terminate(_Reason, _State, #?MODULE{sslsock = none, sock = Sock}) ->
    gen_tcp:close(Sock);
terminate(_Reason, _State, #?MODULE{sslsock = SslSock, sock = Sock}) ->
    ssl:close(SslSock),
    gen_tcp:close(Sock).

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
