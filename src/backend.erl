%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(backend).
-behaviour(gen_fsm).

-include("x224.hrl").
-include("mcsgcc.hrl").
-include("tsud.hrl").
-include("rdpp.hrl").

-export([start_link/4]).
-export([initiation/2, proxy_intercept/2, proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid(), Address :: inet:ip_address() | inet:hostname(), Port :: inet:port_number(), OrigCr :: tuple()) -> {ok, pid()}.
start_link(Frontend, Address, Port, OrigCr) ->
    gen_fsm:start_link(?MODULE, [Frontend, Address, Port, OrigCr], []).

-record(data, {addr, port, sock, sslsock=none, themref=0, usref=0, unused, frontend, origcr}).

%% @private
init([Frontend, Address, Port, OrigCr]) ->
    process_flag(trap_exit, true),
    random:seed(erlang:now()),
    case gen_tcp:connect(Address, Port, [binary, {active, once}, {packet, raw}, {nodelay, true}]) of
        {ok, Sock} ->
            Cr = OrigCr#x224_cr{rdp_protocols = [ssl]},
            io:format("backend send cr: ~s\n", [x224:pretty_print(Cr)]),
            {ok, CrData} = x224:encode(Cr),
            {ok, Packet} = tpkt:encode(CrData),
            ok = gen_tcp:send(Sock, Packet),
            {ok, initiation, #data{addr = Address, port = Port, frontend = Frontend, sock = Sock, usref = OrigCr#x224_cr.src, origcr = OrigCr}};

        {error, Reason} ->
            {stop, Reason}
    end.

%initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = error, rdp_error = ssl_not_allowed} = Pkt}, #data{addr = Address, port = Port, sock = Sock, usref = UsRef} = Data) ->
%   gen_tcp:close(Sock),
%   case gen_tcp:connect(Address, Port, [binary, {active, once}, {packet, tpkt}, {nodelay, true}]) of
%       {ok, NewSock} ->
%           Cr = #x224_cr{src = UsRef, dst = 0, rdp_protocols = []},
%           {ok, CrData} = x224:encode(Cr),
%           {ok, Packet} = tpkt:encode(CrData),
%           ok = gen_tcp:send(NewSock, Packet),
%           {next_state, initiation, Data#data{sock = NewSock}};
%
%       {error, Reason} ->
%           {stop, Reason, Data}
%   end;

initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = ok} = Pkt}, #data{usref = UsRef, sock = Sock, frontend = Frontend} = Data) ->
    #x224_cc{src = ThemRef, rdp_selected = Selected, rdp_flags = Flags} = Pkt,
    io:format("backend got cc: ~s\n", [x224:pretty_print(Pkt)]),

    HasSsl = lists:member(ssl, Selected),

    if HasSsl ->
        inet:setopts(Sock, [{packet, raw}]),
        {ok, SslSock} = ssl:connect(Sock, [{verify, verify_none}]),
        ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),

        gen_fsm:send_event(Frontend, {backend_ready, self(), SslSock, Pkt}),

        {next_state, proxy_intercept, Data#data{sslsock = SslSock, themref = ThemRef}};
    true ->
        gen_tcp:close(Sock),
        {stop, no_ssl, Data}
    end.

proxy_intercept({data, Bin}, #data{sslsock = SslSock, frontend = Frontend, origcr = OrigCr} = Data) ->
    case rdpp:decode_connseq(Bin) of
        {ok, {mcs_pdu, Cr = #mcs_cr{data = TsudsBin0}}, Rem} ->
            {ok, Tsuds0} = tsud:decode(TsudsBin0),
            TsudSvrCore0 = lists:keyfind(tsud_svr_core, 1, Tsuds0),
            TsudSvrCore1 = TsudSvrCore0#tsud_svr_core{requested = OrigCr#x224_cr.rdp_protocols},
            io:format("rewriting tsud: ~s\n", [tsud:pretty_print(TsudSvrCore1)]),
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
    {next_state, proxy_intercept, Data}.

proxy({data, Bin}, #data{sslsock = SslSock, frontend = Frontend} = Data) ->
    gen_fsm:send_event(Frontend, {backend_data, self(), Bin}),
    {next_state, proxy, Data};

proxy({frontend_data, Frontend, Bin}, #data{sock = Sock, sslsock = SslSock, frontend = Frontend} = Data) ->
    if SslSock =:= none ->
        ok = gen_tcp:send(Sock, Bin);
    true ->
        ok = ssl:send(SslSock, Bin)
    end,
    {next_state, proxy, Data}.

debug_print_data(<<>>) -> ok;
debug_print_data(Bin) ->
    case rdpp:decode_connseq(Bin) of
        {ok, {fp_pdu, Pdu}, Rem} ->
            %error_logger:info_report(["backend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
            debug_print_data(Rem);
        {ok, {x224_pdu, Pdu}, Rem} ->
            error_logger:info_report(["backend rx x224:\n", x224:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu = #mcs_srv_data{data = RdpData, channel = Chan}}, Rem} ->
            case rdpp:decode_basic(RdpData) of
                {ok, Rec} ->
                    {ok, RdpData} = rdpp:encode_basic(Rec),
                    error_logger:info_report(["backend rx rdp_basic:\n", rdpp:pretty_print(Rec)]);
                _ ->
                    case rdpp:decode_sharecontrol(RdpData) of
                        {ok, #ts_demand{} = Rec} ->
                            case rdpp:encode_sharecontrol(Rec) of
                                {ok, RdpData} -> ok;
                                {ok, OtherData} ->
                                    file:write_file("backend_orig", RdpData),
                                    file:write_file("backend_reenc", OtherData),
                                    error_logger:info_report(io_lib:format("original data = ~p\nreenc data = ~p\n", [RdpData, OtherData]));
                                _ -> error(fail_reencode)
                            end,
                            error_logger:info_report(["backend rx rdp_sharecontrol\n", rdpp:pretty_print(Rec)]);
                        {ok, Rec} ->
                            error_logger:info_report(["backend rx rdp_sharecontrol\n", rdpp:pretty_print(Rec)]);
                        _ ->
                            error_logger:info_report(["backend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]])
                    end
            end,
            debug_print_data(Rem);
        {ok, {mcs_pdu, McsCr = #mcs_cr{}}, Rem} ->
            {ok, Tsuds} = tsud:decode(McsCr#mcs_cr.data),
            error_logger:info_report(["backend rx cr with tsuds: ", tsud:pretty_print(Tsuds)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, #mcs_tir{}}, Rem} ->
            {ok, Data, _} = tpkt:decode(Bin),
            {ok, X224Pdu} = x224:decode(Data),
            error_logger:info_report([{decode_cr, mcsgcc:decode_cr(X224Pdu#x224_dt.data)}, {data, Bin}]),
            file:write_file("bad_cr", Bin),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu}, Rem} ->
            error_logger:info_report(["backend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]]),
            debug_print_data(Rem);
        {ok, Something, Rem} ->
            error_logger:info_report([{backend_unknown, Something},{remaining, Rem}]);
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
            error_logger:info_report([{backend_out, Other}]),
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
terminate(_Reason, _State, _Data) ->
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
