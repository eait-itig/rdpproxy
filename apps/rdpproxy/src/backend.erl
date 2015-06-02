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

-include_lib("rdp_proto/include/x224.hrl").
-include_lib("rdp_proto/include/mcsgcc.hrl").
-include_lib("rdp_proto/include/tsud.hrl").
-include_lib("rdp_proto/include/rdpp.hrl").

-export([start_link/4, probe/2]).
-export([initiation/2, proxy_intercept/2, proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid(), Address :: inet:ip_address() | inet:hostname(), Port :: inet:port_number(), OrigCr :: tuple()) -> {ok, pid()}.
start_link(Frontend, Address, Port, OrigCr) ->
    gen_fsm:start_link(?MODULE, [Frontend, Address, Port, OrigCr], []).

probe(Address, Port) ->
    case (catch gen_fsm:start(?MODULE, [self(), Address, Port], [{timeout, 5000}])) of
        {ok, Pid} ->
            MonRef = monitor(process, Pid),
            probe_rx(Pid, MonRef, {error, bad_host});
        {'EXIT', Reason} -> {error, Reason};
        Err -> Err
    end.

probe_rx(Pid, MonRef, RetVal) ->
    receive
        {'$gen_event', {backend_ready, Pid, _, _}} ->
            gen_fsm:send_event(Pid, close),
            probe_rx(Pid, MonRef, ok);
        {'DOWN', MonRef, process, Pid, no_ssl} ->
            {error, no_ssl};
        {'DOWN', MonRef, process, Pid, _} ->
            RetVal
    after 10000 ->
        exit(Pid, kill),
        probe_rx(Pid, MonRef, {error, timeout})
    end.

-record(data, {addr, port, sock, sslsock=none, themref=0, usref=0, unused, frontend, origcr}).

%% @private
init([Frontend, Address, Port]) ->
    init([Frontend, Address, Port, #x224_cr{
        class = 0, dst = 0, src = crypto:rand_uniform(2000,9999)
        }]);
init([Frontend, Address, Port, OrigCr]) ->
    process_flag(trap_exit, true),
    random:seed(os:timestamp()),
    lager:debug("backend for frontend ~p", [Frontend]),
    case gen_tcp:connect(Address, Port, [binary, {active, once}, {packet, raw}, {nodelay, true}], 2000) of
        {ok, Sock} ->
            Cr = OrigCr#x224_cr{rdp_protocols = [ssl]},
            lager:debug("backend connected to ~p", [Address]),
            {ok, CrData} = x224:encode(Cr),
            {ok, Packet} = tpkt:encode(CrData),
            ok = gen_tcp:send(Sock, Packet),
            {ok, initiation, #data{addr = Address, port = Port, frontend = Frontend, sock = Sock, usref = OrigCr#x224_cr.src, origcr = OrigCr}};

        {error, Reason} ->
            db_host_meta:put(Address, [{<<"status">>,<<"dead">>}, {<<"sessions">>, []}]),
            {stop, Reason}
    end.

initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = error, rdp_error = ssl_not_allowed} = Pkt},
        #data{addr = Address, port = Port, sock = Sock, usref = UsRef} = Data) ->
    db_host_meta:put(Address, [{<<"status">>,<<"dead">>}, {<<"sessions">>, []}]),
    {stop, no_ssl, Data};

initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = ok} = Pkt}, #data{usref = UsRef, sock = Sock, frontend = Frontend, addr = Address} = Data) ->
    #x224_cc{src = ThemRef, rdp_selected = Selected, rdp_flags = Flags} = Pkt,

    HasSsl = lists:member(ssl, Selected),

    if HasSsl ->
        inet:setopts(Sock, [{packet, raw}]),
        {ok, SslSock} = ssl:connect(Sock,
            rdpproxy:config([backend, ssl_options], [{verify, verify_none}])),
        ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),

        gen_fsm:send_event(Frontend, {backend_ready, self(), SslSock, Pkt}),

        {next_state, proxy_intercept, Data#data{sslsock = SslSock, themref = ThemRef}};
    true ->
        lager:debug("upstream server rejected SSL, dying"),
        gen_tcp:close(Sock),
        db_host_meta:put(Address, [{<<"status">>,<<"dead">>}, {<<"sessions">>, []}]),
        {stop, no_ssl, Data}
    end.

proxy_intercept({data, Bin}, #data{sslsock = SslSock, frontend = Frontend, origcr = OrigCr} = Data) ->
    case rdpp:decode_connseq(Bin) of
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
            gen_fsm:send_event(Frontend, {backend_data, self(), <<OutPkt/binary, Rem/binary>>}),
            {next_state, proxy, Data};
        _ ->
            gen_fsm:send_event(Frontend, {backend_data, self(), Bin}),
            {next_state, proxy_intercept, Data}
    end;

proxy_intercept({frontend_data, Frontend, Bin}, #data{sock = Sock, sslsock = SslSock, frontend = Frontend} = Data) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy_intercept, Data};

proxy_intercept(close, Data) ->
    {stop, normal, Data}.

proxy({data, Bin}, #data{sslsock = SslSock, frontend = Frontend} = Data) ->
    gen_fsm:send_event(Frontend, {backend_data, self(), Bin}),
    {next_state, proxy, Data};

proxy({frontend_data, Frontend, Bin}, #data{sock = Sock, sslsock = SslSock, frontend = Frontend} = Data) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy, Data};

proxy(close, Data) ->
    {stop, normal, Data}.

debug_print_data(<<>>) -> ok;
debug_print_data(Bin) ->
    case rdpp:decode_connseq(Bin) of
        {ok, {fp_pdu, Pdu}, Rem} ->
            %error_logger:info_report(["backend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
            debug_print_data(Rem);
        {ok, {x224_pdu, Pdu}, Rem} ->
            lager:info("backend rx x224: ~s", [x224:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu = #mcs_srv_data{data = RdpData, channel = Chan}}, Rem} ->
            case rdpp:decode_basic(RdpData) of
                {ok, Rec} ->
                    {ok, RdpData} = rdpp:encode_basic(Rec),
                    lager:info("backend rx rdp_basic: ~s", [rdpp:pretty_print(Rec)]);
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
                        _ ->
                            lager:info("backend rx mcs: ~s", [mcsgcc:pretty_print(Pdu)])
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
            lager:info("backend_unknown: ~p, rem = ~p", [Something, Rem]);
        {error, Reason} ->
            ok
    end.

%% @private
handle_info({tcp, Sock, Bin}, State, #data{sslsock = SslSock, sock = Sock} = Data) ->
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

handle_info({ssl, SslSock, Bin}, State, #data{sslsock = SslSock} = Data)
        when (State =:= proxy) orelse (State =:= proxy_intercept) ->
    ?MODULE:State({data, Bin}, Data);
handle_info({ssl, SslSock, Bin}, State, #data{sock = Sock, sslsock = SslSock} = Data) ->
    handle_info({tcp, Sock, Bin}, State, Data);

handle_info({ssl_closed, SslSock}, State, #data{sslsock = SslSock} = Data) ->
    {stop, normal, Data};

handle_info({tcp_closed, Sock}, State, #data{sock = Sock} = Data) ->
    {stop, normal, Data};

handle_info(_Msg, State, Data) ->
    {next_state, State, Data}.

%% @private
terminate(_Reason, _State, #data{sslsock = none, sock = Sock}) ->
    gen_tcp:close(Sock);
terminate(_Reason, _State, #data{sslsock = SslSock, sock = Sock}) ->
    ssl:close(SslSock),
    gen_tcp:close(Sock).

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
