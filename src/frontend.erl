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
-include("kbd.hrl").
-include("tsud.hrl").
-include("session.hrl").
-include("rdpp.hrl").

-export([start_link/1]).
-export([wait_control/2, initiation/2, mcs_connect/2, mcs_attach_user/2, mcs_chans/2, rdp_clientinfo/2, rdp_capex/2, init_finalize/2, proxy/2, wait_proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Sock :: term()) -> {ok, pid()}.
start_link(Sock) ->
	gen_fsm:start_link(?MODULE, [Sock], []).

-record(data, {sock, sslsock=none, themref=0, themuser=0, usref=0, backend=none, queue=[], waitchans=[], chans=[], iochan=0}).

send_dpdu(SslSock, McsPkt) ->
	{ok, McsData} = mcsgcc:encode_dpdu(McsPkt),
	{ok, DtData} = x224:encode(#x224_dt{data = McsData}),
	{ok, Packet} = tpkt:encode(DtData),
	ok = ssl:send(SslSock, Packet).

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
	error_logger:info_report(["tsuds: ", tsud:pretty_print(Tsuds)]),
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

	{next_state, mcs_attach_user, Data#data{waitchans = Chans, iochan = 1003}}.

mcs_attach_user({mcs_pdu, #mcs_edr{}}, Data) ->
	{next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_aur{}}, #data{sslsock = SslSock} = Data) ->
	send_dpdu(SslSock, #mcs_auc{user = Data#data.themuser, status = 'rt-successful'}),
	{next_state, mcs_chans, Data}.

mcs_chans({mcs_pdu, #mcs_cjr{user = User, channel = Chan}}, #data{sslsock = SslSock, themuser = User, waitchans = Chans, chans = All} = Data) ->

	NewChans = Chans -- [Chan],
	NewData = Data#data{waitchans = NewChans, chans = [Chan|All]},

	send_dpdu(SslSock, #mcs_cjc{user = User, channel = Chan, status = 'rt-successful'}),

	if (length(NewChans) == 0) ->
		error_logger:info_report([{mcs_chans, all_ok}, {chans, NewData#data.chans}]),
		{next_state, rdp_clientinfo, NewData};
	true ->
		{next_state, mcs_chans, NewData}
	end.

rdp_clientinfo({mcs_pdu, #mcs_data{data = RdpData, channel = Chan}}, #data{sslsock = SslSock, iochan = Chan} = Data) ->
	case rdpp:decode_basic(RdpData) of
		{ok, #ts_info{} = InfoPkt} ->
			error_logger:info_report(["info packet: ", rdpp:pretty_print(InfoPkt)]),

			{ok, LicData} = rdpp:encode_basic(#ts_license_vc{}),
			send_dpdu(SslSock, #mcs_srv_data{channel = Chan, data = LicData}),

			{ok, DaPkt} = rdpp:encode_sharecontrol(#ts_demand{
				shareid = (Data#data.themuser bsl 16) + 1,
				sourcedesc = <<"rdpproxy", 0>>,
				capabilities = [
					#ts_cap_general{},
					#ts_cap_share{},
					#ts_cap_order{},
					#ts_cap_bitmap{bpp = 16},
					#ts_cap_pointer{},
					#ts_cap_input{},
					#ts_cap_font{}
				]
			}),
			send_dpdu(SslSock, #mcs_srv_data{channel = Chan, data = DaPkt}),

			{next_state, rdp_capex, Data};
		{ok, RdpPkt} ->
			error_logger:info_report(["rdp packet: ", rdpp:pretty_print(RdpPkt)]),
			{next_state, rdp_clientinfo, Data};
		_ ->
			{stop, bad_protocol, Data}
	end.

rdp_capex({mcs_pdu, #mcs_data{data = RdpData, channel = Chan}}, #data{sslsock = SslSock, iochan = Chan} = Data) ->
	case rdpp:decode_sharecontrol(RdpData) of
		{ok, #ts_confirm{} = Pkt} ->
			error_logger:info_report(["confirm: ", rdpp:pretty_print(Pkt)]),
			{next_state, init_finalize, Data};
		Other ->
			{stop, Other, Data}
	end.

init_finalize({mcs_pdu, #mcs_data{data = RdpData, channel = Chan}}, #data{sslsock = SslSock, iochan = Chan} = Data) ->
	case rdpp:decode_sharecontrol(RdpData) of
		{ok, #ts_sharedata{shareid = ShareId, data = #ts_sync{}}} ->
			{ok, SyncData} = rdpp:encode_sharecontrol(#ts_sharedata{shareid = ShareId, data = #ts_sync{}}),
			send_dpdu(SslSock, #mcs_srv_data{channel = Chan, data = SyncData}),
			{next_state, init_finalize, Data};

		{ok, #ts_sharedata{shareid = ShareId, data = #ts_control{action=cooperate}}} ->
			{ok, CoopData} = rdpp:encode_sharecontrol(#ts_sharedata{shareid = ShareId, data = #ts_control{action = cooperate}}),
			send_dpdu(SslSock, #mcs_srv_data{channel = Chan, data = CoopData}),
			{next_state, init_finalize, Data};

		{ok, #ts_sharedata{shareid = ShareId, data = #ts_control{action=request}}} ->
			{ok, GrantData} = rdpp:encode_sharecontrol(#ts_sharedata{shareid = ShareId, data = #ts_control{action = granted, controlid = 16#3ea, grantid=Data#data.themuser}}),
			send_dpdu(SslSock, #mcs_srv_data{channel = Chan, data = GrantData}),
			{next_state, init_finalize, Data};

		{ok, #ts_sharedata{shareid = ShareId, data = #ts_fontlist{}}} ->
			{ok, FontMap} = rdpp:encode_sharecontrol(#ts_sharedata{shareid = ShareId, data = #ts_fontmap{}}),
			send_dpdu(SslSock, #mcs_srv_data{channel = Chan, data = FontMap}),

			{ok, Updates} = rdpp:encode_sharecontrol(#ts_sharedata{shareid = ShareId, data = #ts_update_orders{orders = [
					#ts_order_opaquerect{dest=[100,100], size=[500,500], color=[255,200,200]},
					#ts_order_line{start=[100,100], finish=[500,500], color=[255,255,255]}
				]}}),
			send_dpdu(SslSock, #mcs_srv_data{channel = Chan, data = Updates}),

			{next_state, init_finalize, Data};

		{ok, #ts_sharedata{} = SD} ->
			error_logger:info_report(["sharedata: ", rdpp:pretty_print(SD)]),
			{next_state, init_finalize, Data};

		Other ->
			{stop, Other, Data}
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
