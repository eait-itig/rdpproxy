%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(frontend).
-behaviour(gen_fsm).

-include("x224.hrl").
-include("mcsgcc.hrl").
-include("tsud.hrl").
-include("session.hrl").

-export([start_link/1]).
-export([wait_control/2, initiation/2, mcs_connect/2, mcs_attach_user/2, mcs_chans/2, proxy/2, wait_proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Sock :: term()) -> {ok, pid()}.
start_link(Sock) ->
	gen_fsm:start_link(?MODULE, [Sock], []).

-record(data, {sock, sslsock=none, themref=0, themuser=0, usref=0, backend=none, queue=[], waitchans=[], chans=[]}).

%% @private
init([Sock]) ->
	process_flag(trap_exit, true),
	random:seed(erlang:now()),
	{ok, wait_control, #data{sock = Sock}}.

%% @doc Waiting for control of the socket to be given by frontend_listener
wait_control(control_given, #data{sock = Sock} = Data) ->
	inet:setopts(Sock, [{packet, tpkt}, {active, once}]),
	{next_state, initiation, Data}.

initiation({x224_pdu, #x224_cr{class = 0, dst = 0} = Pkt}, #data{sock = Sock} = Data) ->
	#x224_cr{src = ThemRef, rdp_cookie = Cookie, rdp_protocols = Protos} = Pkt,

	UsRef = random:uniform(1 bsl 15),
	ThemUser = 1000 + random:uniform(1000),
	NewData = Data#data{themref = ThemRef, usref = UsRef, themuser = ThemUser},
	HasSsl = lists:member(ssl, Protos),

	if HasSsl ->
		Resp = #x224_cc{src = UsRef, dst = ThemRef, rdp_selected = [ssl], rdp_flags = [extdata]},
		{ok, RespData} = x224:encode(Resp),
		{ok, Packet} = tpkt:encode(RespData),
		gen_tcp:send(Sock, Packet),

		inet:setopts(Sock, [{packet, raw}]),
		{ok, SslSock} = ssl:ssl_accept(Sock, [{certfile, "etc/cert.pem"}, {keyfile, "etc/key.pem"}]),
		ok = ssl:setopts(SslSock, [binary, {active, true}]),

		case session_mgr:get(Cookie) of
			{ok, #session{host = Host, port = Port}} ->
				Backend = backend:start_link(self(), Host, Port),
				{next_state, wait_proxy, NewData#data{sslsock = SslSock, backend = Backend}};
			_ ->
				{next_state, mcs_connect, NewData#data{sslsock = SslSock}}
		end;
	true ->
		Resp = #x224_cc{src = UsRef, dst = ThemRef, rdp_status = error, rdp_error = ssl_required},
		{ok, RespData} = x224:encode(Resp),
		{ok, Packet} = tpkt:encode(RespData),
		gen_tcp:send(Sock, Packet),

		gen_tcp:close(Sock),
		{stop, bad_protocol, Data}
	end.

mcs_connect({mcs_pdu, #mcs_ci{} = McsCi}, #data{sslsock = SslSock} = Data) ->
	{ok, Tsuds} = tsud:decode(McsCi#mcs_ci.data),
	lists:foreach(fun(Tsud) -> error_logger:info_report(["tsud: ", tsud:pretty_print(Tsud)]) end, Tsuds),
	CNet = lists:keyfind(tsud_net, 1, Tsuds),

	{ok, Core} = tsud:encode(#tsud_svr_core{requested = [ssl]}),
	{Net, Chans} = case CNet of
		false ->
			{ok, N} = tsud:encode(#tsud_svr_net{iochannel = 1003, channels = []}),
			{N, [1003]};

		#tsud_net{channels = InChans} ->
			{_, OutChans} = lists:foldl(fun(Chan, {N, Cs}) -> {N+1, [N|Cs]} end, {1004, []}, InChans),
			{ok, N} = tsud:encode(#tsud_svr_net{iochannel = 1003, channels = OutChans}),
			{N, [1003|OutChans]}
	end,
	{ok, Sec} = tsud:encode(#tsud_svr_security{method=none, level=none}),
	OutTsuds = <<Core/binary, Net/binary, Sec/binary>>,

	{ok, Cr} = mcsgcc:encode_cr(#mcs_cr{data = OutTsuds}),
	{ok, DtData} = x224:encode(#x224_dt{data = Cr}),
	{ok, Packet} = tpkt:encode(DtData),
	ok = ssl:send(SslSock, Packet),

	{next_state, mcs_attach_user, Data#data{waitchans = Chans}}.

mcs_attach_user({mcs_pdu, #mcs_edr{}}, Data) ->
	{next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_aur{}}, #data{sslsock = SslSock} = Data) ->
	{ok, Auc} = mcsgcc:encode_dpdu(#mcs_auc{user = Data#data.themuser, status = 'rt-successful'}),
	{ok, DtData} = x224:encode(#x224_dt{data = Auc}),
	{ok, Packet} = tpkt:encode(DtData),
	ok = ssl:send(SslSock, Packet),
	{next_state, mcs_chans, Data}.

mcs_chans({mcs_pdu, #mcs_cjr{user = User, channel = Chan}}, #data{sslsock = SslSock, themuser = User, waitchans = Chans, chans = All} = Data) ->

	NewChans = Chans -- [Chan],
	NewData = Data#data{waitchans = NewChans, chans = [Chan|All]},

	{ok, Cjc} = mcsgcc:encode_dpdu(#mcs_cjc{user = User, channel = Chan, status = 'rt-successful'}),
	{ok, DtData} = x224:encode(#x224_dt{data = Cjc}),
	{ok, Packet} = tpkt:encode(DtData),
	ok = ssl:send(SslSock, Packet),

	if (length(NewChans) == 0) ->
		error_logger:info_report([{mcs_chans, all_ok}, {chans, NewData#data.chans}]),
		{next_state, rdp_clientinfo, NewData};
	true ->
		{next_state, mcs_chans, NewData}
	end.

wait_proxy({x224_pdu, Pkt}, #data{queue = Queue} = Data) ->
	{next_state, wait_proxy, Data#data{queue = Queue ++ [Pkt]}};

wait_proxy({backend_ready, Backend}, #data{queue = Queue, backend = Backend} = Data) ->
	lists:foreach(fun(Pkt) ->
		gen_fsm:send_event(Backend, {frontend_pdu, self(), Pkt})
	end, Queue),
	{next_state, proxy, Data#data{queue = []}}.

proxy({x224_pdu, Pkt}, #data{sslsock = SslSock, backend = Backend} = Data) ->
	gen_fsm:send_event(Backend, {frontend_pdu, self(), Pkt}),
	{next_state, proxy, Data};

proxy({backend_pdu, Backend, Pkt}, #data{sslsock = SslSock, backend = Backend} = Data) ->
	{ok, PktData} = x224:encode(Pkt),
	{ok, Packet} = tpkt:encode(PktData),
	error_logger:info_report([{frontend_send, Packet}]),
	ssl:send(SslSock, Packet),
	{next_state, proxy, Data}.

%% @private
handle_info({tcp, Sock, Bin}, State, #data{sock = Sock} = Data) ->
	error_logger:info_report([{frontend_recv, Bin}]),
	case tpkt:decode(Bin) of
		{ok, Body} ->
			case x224:decode(Body) of
				{ok, #x224_dt{data = McsData} = Pdu} ->
					case mcsgcc:decode(McsData) of
						{ok, McsPkt} ->
							error_logger:info_report(["frontend rx mcs: ", mcsgcc:pretty_print(McsPkt)]),
							?MODULE:State({mcs_pdu, McsPkt}, Data);
						_ ->
							?MODULE:State({x224_pdu, Pdu}, Data)
					end;
				{ok, Pdu} ->
					error_logger:info_report(["frontend rx x224: ", x224:pretty_print(Pdu)]),
					?MODULE:State({x224_pdu, Pdu}, Data);
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
