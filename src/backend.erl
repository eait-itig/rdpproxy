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

-export([start_link/3]).
-export([initiation/2, mcs_connect/2, proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid(), Address :: inet:ip_address() | inet:hostname(), Port :: inet:port_number()) -> {ok, pid()}.
start_link(Frontend, Address, Port) ->
	gen_fsm:start_link(?MODULE, [Frontend, Address, Port], []).

-record(data, {addr, port, sock, sslsock=none, themref=0, usref=0, frontend}).

%% @private
init([Frontend, Address, Port]) ->
	process_flag(trap_exit, true),
	random:seed(erlang:now()),
	UsRef = random:uniform(1 bsl 15),
	case gen_tcp:connect(Address, Port, [binary, {active, once}, {packet, tpkt}]) of
		{ok, Sock} ->
			Cr = #x224_cr{src = UsRef, dst = 0, rdp_protocols = [ssl]},
			{ok, CrData} = x224:encode(Cr),
			{ok, Packet} = tpkt:encode(CrData),
			ok = gen_tcp:send(Sock, Packet),
			{ok, initiation, #data{addr = Address, port = Port, frontend = Frontend, sock = Sock, usref = UsRef}};

		{error, Reason} ->
			{stop, Reason}
	end.

initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = error, rdp_error = ssl_not_allowed} = Pkt}, #data{addr = Address, port = Port, sock = Sock, usref = UsRef} = Data) ->
	gen_tcp:close(Sock),
	case gen_tcp:connect(Address, Port, [binary, {active, once}, {packet, tpkt}]) of
		{ok, NewSock} ->
			Cr = #x224_cr{src = UsRef, dst = 0, rdp_protocols = []},
			{ok, CrData} = x224:encode(Cr),
			{ok, Packet} = tpkt:encode(CrData),
			ok = gen_tcp:send(NewSock, Packet),
			{next_state, initiation, Data#data{sock = NewSock}};

		{error, Reason} ->
			{stop, Reason, Data}
	end;

initiation({pdu, #x224_cc{class = 0, dst = UsRef, rdp_status = ok} = Pkt}, #data{usref = UsRef, sock = Sock, frontend = Frontend} = Data) ->
	#x224_cc{src = ThemRef, rdp_selected = Selected, rdp_flags = Flags} = Pkt,

	HasSsl = lists:member(ssl, Selected),

	if HasSsl ->
		inet:setopts(Sock, [{packet, raw}]),
		{ok, SslSock} = ssl:connect(Sock, [{verify, verify_none}]),
		ok = ssl:setopts(SslSock, [binary, {active, true}]),

		{ok, Core} = tsud:encode(#tsud_core{width=1024, height=768, selected=[ssl]}),
		{ok, Cluster} = tsud:encode(#tsud_cluster{version=4}),
		{ok, Sec} = tsud:encode(#tsud_security{methods = []}),
		Tsuds = <<Core/binary, Cluster/binary, Sec/binary>>,
		{ok, Ci} = mcsgcc:encode_ci(#mcs_ci{data = Tsuds, conf_name="0"}),
		{ok, DtData} = x224:encode(#x224_dt{data = Ci}),
		{ok, Packet} = tpkt:encode(DtData),
		ok = ssl:send(SslSock, Packet),

		gen_fsm:send_event(Frontend, {backend_ready, self()}),

		{next_state, mcs_connect, Data#data{sslsock = SslSock, themref = ThemRef}};
	true ->
		inet:setopts(Sock, [{active, true}]),

		{ok, Core} = tsud:encode(#tsud_core{width=1024, height=768, selected=[]}),
		{ok, Cluster} = tsud:encode(#tsud_cluster{version=4}),
		{ok, Sec} = tsud:encode(#tsud_security{methods = []}),
		Tsuds = <<Core/binary, Cluster/binary, Sec/binary>>,
		{ok, Ci} = mcsgcc:encode_ci(#mcs_ci{data = Tsuds, conf_name="0"}),
		{ok, DtData} = x224:encode(#x224_dt{data = Ci}),
		{ok, Packet} = tpkt:encode(DtData),
		ok = gen_tcp:send(Sock, Packet),

		gen_fsm:send_event(Frontend, {backend_ready, self()}),

		{next_state, mcs_connect, Data#data{themref = ThemRef}}
	end.

mcs_connect({pdu, #x224_dt{data = McsPkt}}, #data{sslsock = SslSock, sock = Sock} = Data) ->
	case mcsgcc:decode_cr(McsPkt) of
		{ok, McsCr} ->
			{ok, Tsuds} = tsud:decode(McsCr#mcs_cr.data),
			lists:foreach(fun(Tsud) ->
				error_logger:info_report(["tsud: ", tsud:pretty_print(Tsud)])
			end, Tsuds),
			{next_state, mcs_connect, Data};
		Other ->
			error_logger:info_report([{mcsgcc_err, Other}]),
			if (SslSock =:= none) ->
				gen_tcp:close(Sock);
			true ->
				ssl:close(SslSock)
			end,
			{next_state, mcs_connect, Data}
			%{stop, bad_protocol, Data}
	end.

proxy({pdu, Pkt}, #data{sslsock = SslSock, frontend = Frontend} = Data) ->
	gen_fsm:send_event(Frontend, {backend_pdu, self(), Pkt}),
	{next_state, proxy, Data};

proxy({frontend_pdu, Frontend, Pkt}, #data{sock = Sock, sslsock = SslSock, frontend = Frontend} = Data) ->
	{ok, PktData} = x224:encode(Pkt),
	{ok, Packet} = tpkt:encode(PktData),
	if SslSock =:= none ->
		error_logger:info_report([{backend_send, Packet}]),
		ok = gen_tcp:send(Sock, Packet);
	true ->
		error_logger:info_report([{backend_send_ssl, Packet}]),
		ok = ssl:send(SslSock, Packet)
	end,
	{next_state, proxy, Data}.

%% @private
handle_info({tcp, Sock, Bin}, State, #data{sock = Sock} = Data) ->
	error_logger:info_report([{backend_recv, Bin}]),
	case tpkt:decode(Bin) of
		{ok, Body} ->
			case x224:decode(Body) of
				{ok, Pdu} ->
					error_logger:info_report(["backend received\n", x224:pretty_print(Pdu)]),
					?MODULE:State({pdu, Pdu}, Data);
				{error, _} ->
					?MODULE:State({data, Body}, Data)
			end;
		{error, Reason} ->
			error_logger:info_report([{bad_tpkt, Reason}]),
			{next_state, State, Data}
	end;

handle_info({ssl, SslSock, Bin}, State, #data{sock = Sock, sslsock = SslSock} = Data) ->
	handle_info({tcp, Sock, Bin}, State, Data);

handle_info({tcp_closed, Sock}, State, #data{sock = Sock} = Data) ->
	?MODULE:State(disconnect, Data);

handle_info(_Msg, State, Data) ->
	{next_state, State, Data}.

%% @private
terminate(_Reason, _State, _Data) ->
	ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
	{ok, State}.
