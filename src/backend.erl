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

-export([start_link/3]).
-export([initiation/2, proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid(), Address :: inet:ip_address() | inet:hostname(), Port :: inet:port_number()) -> {ok, pid()}.
start_link(Frontend, Address, Port) ->
	gen_fsm:start_link(?MODULE, [Frontend, Address, Port], []).

-record(data, {addr, port, sock, sslsock=none, themref=0, usref=0, frontend}).

%% @private
init([Frontend, Address, Port]) ->
	process_flag(trap_exit, true),
	random:seed(erlang:now()),
	UsRef = 0,
	case gen_tcp:connect(Address, Port, [binary, {active, once}, {packet, tpkt}, {nodelay, true}]) of
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
	case gen_tcp:connect(Address, Port, [binary, {active, once}, {packet, tpkt}, {nodelay, true}]) of
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
		ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),

		gen_fsm:send_event(Frontend, {backend_ready, self(), SslSock}),

		{next_state, proxy, Data#data{sslsock = SslSock, themref = ThemRef}};
	true ->
		gen_tcp:close(Sock),
		{stop, no_ssl, Data}
	end.

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

%% @private
handle_info({tcp, Sock, Bin}, State, #data{sock = Sock} = Data) ->
	error_logger:info_report([{backend_recv, Bin}]),
	case tpkt:decode(Bin) of
		{ok, Body, Rem} ->
			case byte_size(Rem) of
				N when N > 0 -> self() ! {tcp, Sock, Rem};
				_ -> ok
			end,
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

handle_info({ssl, SslSock, Bin}, State = proxy, #data{sslsock = SslSock} = Data) ->
	case rdpp:decode_client(Bin) of
		{ok, {fp_pdu, Pdu}, _} ->
			error_logger:info_report(["backend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
		{ok, {x224_pdu, Pdu}, _} ->
			error_logger:info_report(["backend rx x224:\n", x224:pretty_print(Pdu)]);
		{ok, {mcs_pdu, Pdu = #mcs_srv_data{data = RdpData, channel = Chan}}, _} ->
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
			end;
		{ok, {mcs_pdu, Pdu}, _} ->
			error_logger:info_report(["backend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]]);
		_ -> ok
	end,
	?MODULE:State({data, Bin}, Data);
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
