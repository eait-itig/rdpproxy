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
-include("fastpath.hrl").

-export([start_link/2]).
-export([accept/2, initiation/2, mcs_connect/2, mcs_attach_user/2, mcs_chans/2, rdp_clientinfo/2, rdp_capex/2, init_finalize/2, run_ui/2, run_ui/3, proxy/2, wait_proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Sock :: term(), Sup :: pid()) -> {ok, pid()}.
start_link(Sock, Sup) ->
	gen_fsm:start_link(?MODULE, [Sock, Sup], []).

-record(x224_state, {us=none, them=none}).
-record(mcs_state, {us=none, them=none, iochan=none, msgchan=none, chans=[]}).
-record(data, {lsock, sock, sup, unused, uis=[], sslsock=none, backsock=none, chansavail=[], backend=none, queue=[], waitchans=[], tsud_core={}, tsuds=[], caps=[], askedfor=[], shareid=0, x224=#x224_state{}, mcs=#mcs_state{}, session}).

send_dpdu(SslSock, McsPkt) ->
	{ok, McsData} = mcsgcc:encode_dpdu(McsPkt),
	{ok, DtData} = x224:encode(#x224_dt{data = McsData}),
	{ok, Packet} = tpkt:encode(DtData),
	ok = ssl:send(SslSock, Packet).

send_update(Data = #data{sslsock = SslSock, caps = Caps}, TsUpdate) ->
	#ts_cap_general{flags = Flags} = lists:keyfind(ts_cap_general, 1, Caps),
	case lists:member(fastpath, Flags) of
		%true ->
		%	Bin = fastpath:encode_output(#fp_pdu{flags=[], contents=[TsUpdate]}),
		%	ok = ssl:send(SslSock, Bin);
		_ ->
			#data{shareid = ShareId, mcs = #mcs_state{us = Us, iochan = IoChan}} = Data,
			{ok, Bin} = rdpp:encode_sharecontrol(#ts_sharedata{channel = Us, shareid = ShareId, data = TsUpdate}),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Bin})
	end.

%% @private
init([LSock, Sup]) ->
	random:seed(erlang:now()),
	{ok, accept, #data{sup = Sup, lsock = LSock, chansavail=lists:seq(1002,1002+35)}, 0}.

take_el(El, []) -> {false, []};
take_el(El, [El | Rest]) -> {true, Rest};
take_el(El, [Next | Rest]) ->
	{State, Rem} = take_el(El, Rest),
	{State, [Next | Rem]}.

next_channel(D = #data{chansavail = [Next | Rest]}) ->
	{Next, D#data{chansavail = Rest}}.
next_channel(D = #data{chansavail = Cs}, Pref) ->
	case take_el(Pref, Cs) of
		{true, Without} -> {Pref, D#data{chansavail = Without}};
		{false, [First | Rest]} -> {First, D#data{chansavail = Rest}}
	end.

accept(timeout, D = #data{sup = Sup, lsock = LSock}) ->
	{ok, Sock} = gen_tcp:accept(LSock),
	% start our replacement in the pool
	frontend_sup:start_frontend(Sup),
	inet:setopts(Sock, [{packet, raw}, {active, once}, {nodelay, true}]),
	{next_state, initiation, D#data{sock = Sock}}.

initiation({x224_pdu, #x224_cr{class = 0, dst = 0} = Pkt}, #data{sock = Sock, x224 = X224} = Data) ->
	#x224_cr{src = ThemRef, rdp_cookie = Cookie, rdp_protocols = Protos} = Pkt,
	io:format("frontend got cr: ~s\n", [x224:pretty_print(Pkt)]),

	error_logger:info_report([{them_ref, ThemRef}]),
	NewX224 = X224#x224_state{them = ThemRef},
	NewData = Data#data{x224 = NewX224, askedfor=Protos},
	HasSsl = lists:member(ssl, Protos),

	if HasSsl ->
		case session_mgr:get(Cookie) of
			{ok, Sess = #session{host = Host, port = Port}} ->
				{ok, Backend} = backend:start_link(self(), Host, Port, Pkt),
				{next_state, wait_proxy, NewData#data{backend = Backend, session = Sess}};

			_ ->
				UsRef = 1000 + random:uniform(1000),
				Resp = #x224_cc{src = UsRef, dst = ThemRef, rdp_selected = [ssl], rdp_flags = [extdata,dynvc_gfx]},
				{ok, RespData} = x224:encode(Resp),
				{ok, Packet} = tpkt:encode(RespData),
				gen_tcp:send(Sock, Packet),

				inet:setopts(Sock, [{packet, raw}]),
				{ok, SslSock} = ssl:ssl_accept(Sock, [{certfile, "etc/cert.pem"}, {keyfile, "etc/key.pem"}]),
				ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),
				{next_state, mcs_connect, NewData#data{x224 = NewX224#x224_state{us = UsRef}, sslsock = SslSock}}
		end;
	true ->
		error_logger:info_report([{reject_protos, Protos}]),
		UsRef = 1000 + random:uniform(1000),
		Resp = #x224_cc{src = UsRef, dst = ThemRef, rdp_status = error, rdp_error = ssl_required},
		{ok, RespData} = x224:encode(Resp),
		{ok, Packet} = tpkt:encode(RespData),
		gen_tcp:send(Sock, Packet),

		gen_tcp:close(Sock),
		{stop, normal, Data}
	end.

mcs_connect({x224_pdu, _}, Data) ->
	{next_state, mcs_connect, Data};

mcs_connect({mcs_pdu, #mcs_ci{} = McsCi}, #data{sslsock = SslSock} = Data0) ->
	maybe([
		fun(D) ->
			{ok, Tsuds} = tsud:decode(McsCi#mcs_ci.data),
			error_logger:info_report(["tsuds: ", tsud:pretty_print(Tsuds)]),
			{continue, [D#data{tsuds = Tsuds}, Tsuds, <<>>]}
		end,
		fun(D, Tsuds, SoFar) ->
			% allocate our MCS user
			{MyUser, D2} = next_channel(D, 1002),
			{ThemUser, D3} = next_channel(D2, 1007),
			Mcs = D3#data.mcs,
			D4 = D3#data{mcs = Mcs#mcs_state{us = MyUser, them = ThemUser}},
			error_logger:info_report([{mcs_us, MyUser}, {mcs_them, ThemUser}]),
			{continue, [D4, Tsuds, SoFar]}
		end,
		fun(D, Tsuds, SoFar) ->
			{ok, Core} = tsud:encode(#tsud_svr_core{version=[8,4], requested = D#data.askedfor, capabilities = [dynamic_dst]}),
			{continue, [D, Tsuds, <<SoFar/binary, Core/binary>>]}
		end,
		fun(D, Tsuds, SoFar) ->
			% allocate the I/O channel
			{IoChan, D2} = next_channel(D, 1003),
			Mcs = D2#data.mcs,
			D3 = D2#data{mcs = Mcs#mcs_state{iochan = IoChan}},
			% generate the NET TSUD
			case lists:keyfind(tsud_net, 1, Tsuds) of
				false ->
					{ok, Net} = tsud:encode(#tsud_svr_net{iochannel = IoChan, channels = []}),
					D4 = D3#data{waitchans = [IoChan]},
					{continue, [D4, Tsuds, <<SoFar/binary, Net/binary>>]};

				#tsud_net{channels = ReqChans} ->
					{D4, ChansRev} = lists:foldl(fun(Chan, {DD, Cs}) ->
						case lists:member(init, Chan#tsud_net_channel.flags) of
							true ->
								{C, DD2} = next_channel(DD),
								Mcs0 = DD2#data.mcs,
								Mcs1 = Mcs0#mcs_state{
									chans = [{C, Chan} | Mcs0#mcs_state.chans]},
								DD3 = DD2#data{mcs = Mcs1},
								{DD3, [C | Cs]};
							_ ->
								{DD, [0 | Cs]}
						end
					end, {D3, []}, ReqChans),
					Chans = lists:reverse(ChansRev),
					D5 = D4#data{waitchans = Chans},
					{ok, Net} = tsud:encode(#tsud_svr_net{iochannel = IoChan, channels = Chans}),
					{continue, [D5, Tsuds, <<SoFar/binary, Net/binary>>]}
			end
		end,
		fun(D, Tsuds, SoFar) ->
			{ok, Sec} = tsud:encode(#tsud_svr_security{method = none, level = none}),
			{continue, [D, Tsuds, <<SoFar/binary, Sec/binary>>]}
		end,
		fun(D, Tsuds, SoFar) ->
			case lists:keyfind(tsud_msgchannel, 1, Tsuds) of
				false ->
					{continue, [D, Tsuds, SoFar]};
				_ ->
					%{MsgChan, D2} = next_channel(D),
					%Mcs1 = D2#data.mcs#mcs_state{msgchan = MsgChan},
					%D3 = D2#data{mcs = Mcs1},
					{ok, Bin} = tsud:encode(#tsud_svr_msgchannel{channel = 0}),
					{continue, [D, Tsuds, <<SoFar/binary, Bin/binary>>]}
			end
		end,
		%fun(D, Tsuds, SoFar) ->
		%	case lists:keyfind(tsud_multitransport, 1, Tsuds) of
		%		false ->
		%			{continue, [D, Tsuds, SoFar]};
		%		_ ->
		%			{ok, Bin} = tsud:encode(#tsud_svr_multitransport{}),
		%			{continue, [D, Tsuds, <<SoFar/binary, Bin/binary>>]}
		%	end
		%end,
		fun(D = #data{mcs = Mcs}, Tsuds, SvrTsuds) ->
			{ok, Cr} = mcsgcc:encode_cr(#mcs_cr{data = SvrTsuds, node = Mcs#mcs_state.us}),

			{ok, DebugCr} = mcsgcc:decode_cr(Cr),
			{ok, DebugTsuds} = tsud:decode(SvrTsuds),
			error_logger:info_report(["tsud output: ", tsud:pretty_print(DebugTsuds)]),
			error_logger:info_report(["cr output: ", mcsgcc:pretty_print(DebugCr)]),

			{ok, DtData} = x224:encode(#x224_dt{data = Cr}),
			{ok, Packet} = tpkt:encode(DtData),
			ok = ssl:send(SslSock, Packet),

			TsCore = lists:keyfind(tsud_core, 1, Tsuds),
			{return, {next_state, mcs_attach_user, D#data{tsud_core = TsCore}}}
		end
	], [Data0]);

mcs_connect({mcs_pdu, Pdu}, Data) ->
	error_logger:info_report(["mcs_connect got: ", mcsgcc:pretty_print(Pdu)]),
	{next_state, mcs_connect, Data}.

mcs_attach_user({x224_pdu, _}, Data) ->
	{next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_edr{}}, Data) ->
	{next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_aur{}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them}} = Data) ->
	send_dpdu(SslSock, #mcs_auc{user = Them, status = 'rt-successful'}),
	{next_state, mcs_chans, Data};

mcs_attach_user({mcs_pdu, Pdu}, Data) ->
	error_logger:info_report(["mcs_attach_user got: ", mcsgcc:pretty_print(Pdu)]),
	{next_state, mcs_attach_user, Data}.

mcs_chans({mcs_pdu, #mcs_cjr{user = Them, channel = Chan}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them, us = Us}, waitchans = Chans} = Data) ->

	NewChans = Chans -- [Chan],
	NewData = Data#data{waitchans = NewChans},

	send_dpdu(SslSock, #mcs_cjc{user = Us, channel = Chan, status = 'rt-successful'}),

	if (length(NewChans) == 0) ->
		error_logger:info_report([{mcs_chans, all_ok}, {chans, NewData#data.mcs#mcs_state.chans}]),
		{next_state, rdp_clientinfo, NewData};
	true ->
		{next_state, mcs_chans, NewData}
	end;

mcs_chans({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan} = Pdu}, #data{waitchans = Chans, mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}} = Data) ->
	case rdpp:decode_basic(RdpData) of
		{ok, #ts_info{}} ->
			error_logger:info_report([{got, ts_info}, {missing_chans, Chans}]),
			rdp_clientinfo({mcs_pdu, Pdu}, Data);
		{ok, RdpPkt} ->
			error_logger:info_report(["mcs_chans got: ", rdpp:pretty_print(RdpPkt)]);
		_ ->
			error_logger:info_report(["mcs_chans got: ", mcsgcc:pretty_print(Pdu)])
	end,
	{next_state, mcs_chans, Data};

mcs_chans({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = Them} = Pdu}, #data{mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}} = Data) ->
	case rdpp:decode_basic(RdpData) of
		{ok, RdpPkt} ->
			error_logger:info_report(["mcs_chans got on user chan: ", rdpp:pretty_print(RdpPkt)]);
		_ ->
			error_logger:info_report(["mcs_chans got on user chan: ", mcsgcc:pretty_print(Pdu)])
	end,
	{next_state, mcs_chans, Data}.

rdp_clientinfo({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them, us = Us, iochan = IoChan}} = Data) ->
	case rdpp:decode_basic(RdpData) of
		{ok, #ts_info{} = InfoPkt} ->
			error_logger:info_report(["info packet: ", rdpp:pretty_print(InfoPkt)]),

			{ok, LicData} = rdpp:encode_basic(#ts_license_vc{secflags=[encrypt_license]}),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = LicData}),

			Core = Data#data.tsud_core,
			Rand = 1,
			<<ShareId:32/big>> = <<Rand:16/big, Us:16/big>>,
			{ok, DaPkt} = rdpp:encode_sharecontrol(#ts_demand{
				shareid = ShareId,
				channel = Us,
				sourcedesc = <<"RDP", 0>>,
				capabilities = [
					#ts_cap_share{channel = Us},
					#ts_cap_general{os = [windows, winnt], flags = [suppress_output, refresh_rect, short_bitmap_hdr, autoreconnect, long_creds, salted_mac, fastpath]},
					#ts_cap_vchannel{},
					#ts_cap_font{},
					#ts_cap_bitmap_codecs{codecs = [
						#ts_cap_bitmap_codec{codec = nscodec, id = 1, properties = [{dynamic_fidelity, true}, {subsampling, true}, {color_loss_level, 3}]},
						#ts_cap_bitmap_codec{codec = jpeg, id = 0, properties = [{quality, 85}]}
					]},
					#ts_cap_bitmap{bpp = 24, width = Core#tsud_core.width, height = Core#tsud_core.height},
					#ts_cap_order{},
					#ts_cap_pointer{},
					#ts_cap_input{flags = [mousex, scancodes, unicode, fastpath, fastpath2], kbd_layout = 0, kbd_type = 0, kbd_fun_keys = 0},
					#ts_cap_multifrag{},
					#ts_cap_large_pointer{},
					#ts_cap_colortable{}
				]
			}),
			file:write_file("my_demand", DaPkt),
			{ok, Da} = rdpp:decode_sharecontrol(DaPkt),
			error_logger:info_report(["sending demand packet: ", rdpp:pretty_print(Da)]),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = DaPkt}),

			{next_state, rdp_capex, Data#data{shareid = ShareId}};
		{ok, RdpPkt} ->
			error_logger:info_report(["rdp packet: ", rdpp:pretty_print(RdpPkt)]),
			{next_state, rdp_clientinfo, Data};
		Other ->
			{stop, {bad_protocol, Other}, Data}
	end;

rdp_clientinfo({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = Them} = Pdu}, #data{mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}} = Data) ->
	case rdpp:decode_basic(RdpData) of
		{ok, RdpPkt} ->
			error_logger:info_report(["rdp_clientinfo got on user chan: ", rdpp:pretty_print(RdpPkt)]);
		_ ->
			error_logger:info_report(["rdp_clientinfo got on user chan: ", mcsgcc:pretty_print(Pdu)])
	end,
	{next_state, rdp_clientinfo, Data}.

rdp_capex({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them, iochan = IoChan}, shareid = ShareId} = Data) ->
	case rdpp:decode_sharecontrol(RdpData) of
		{ok, #ts_confirm{shareid = ShareId, capabilities = Caps} = Pkt} ->
			error_logger:info_report(["confirm: ", rdpp:pretty_print(Pkt)]),
			{next_state, init_finalize, Data#data{caps = Caps}};
		Other ->
			{stop, Other, Data}
	end.

init_finalize({fp_pdu, #fp_pdu{contents = Evts}}, #data{} = Data) ->
	{next_state, init_finalize, Data};

init_finalize({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them, us = Us, iochan = IoChan}, shareid = ShareId} = Data) ->
	case rdpp:decode_sharecontrol(RdpData) of
		{ok, #ts_sharedata{shareid = ShareId, data = #ts_sync{}}} ->
			{ok, SyncData} = rdpp:encode_sharecontrol(#ts_sharedata{channel = Us, shareid = ShareId, data = #ts_sync{user = Us}}),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = SyncData}),
			{next_state, init_finalize, Data};

		{ok, #ts_sharedata{shareid = ShareId, data = #ts_control{action=cooperate}}} ->
			{ok, CoopData} = rdpp:encode_sharecontrol(#ts_sharedata{channel = Us, shareid = ShareId, data = #ts_control{action = cooperate, controlid = Us, grantid = Them}}),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = CoopData}),
			{next_state, init_finalize, Data};

		{ok, #ts_sharedata{shareid = ShareId, data = #ts_control{action=request}}} ->
			{ok, GrantData} = rdpp:encode_sharecontrol(#ts_sharedata{channel = Us, shareid = ShareId, data = #ts_control{action = granted, controlid = Us, grantid = Them}}),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = GrantData}),
			{next_state, init_finalize, Data};

		{ok, #ts_sharedata{shareid = ShareId, data = #ts_fontlist{}}} ->
			{ok, FontMap} = rdpp:encode_sharecontrol(#ts_sharedata{channel = Us, shareid = ShareId, data = #ts_fontmap{}}),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = FontMap}),

			{ok, _} = ui_sup:start_ui(self()),
			{next_state, run_ui, Data};

		{ok, #ts_sharedata{} = SD} ->
			error_logger:info_report(["finalize: ", rdpp:pretty_print(SD)]),
			{next_state, init_finalize, Data};

		Other ->
			{stop, Other, Data}
	end.

run_ui(get_canvas, From, D = #data{caps = Caps}) ->
	#ts_cap_bitmap{bpp = Bpp, width = W, height = H} = lists:keyfind(ts_cap_bitmap, 1, Caps),
	gen_fsm:reply(From, {W, H, Bpp}),
	{next_state, run_ui, D}.

run_ui({subscribe, UiFsm}, D = #data{uis = Uis}) ->
	{next_state, run_ui, D#data{uis = [UiFsm | Uis]}};

run_ui({send_update, Update}, D = #data{}) ->
	send_update(D, Update),
	{next_state, run_ui, D};

run_ui({redirect, Cookie, Hostname, Username, Domain, Password}, D = #data{sslsock = SslSock, mcs = #mcs_state{us = Us, iochan = IoChan}, shareid = ShareId}) ->
	GeneralCap = lists:keyfind(ts_cap_general, 1, D#data.caps),
	{ok, Redir} = rdpp:encode_sharecontrol(#ts_redir{
		channel = Us,
		shareid = ShareId,
		sessionid = 0,
		flags = [logon],
		% always send the address if it's the official OSX client (it won't actually redir
		% if we don't, even though this is invalid by the spec)
		address = if GeneralCap#ts_cap_general.os =:= [other,other] ->
			unicode:characters_to_binary(<<Hostname/binary,0>>, latin1, {utf16, little});
			true -> undefined end,
		username = unicode:characters_to_binary(<<Username/binary,0>>, latin1, {utf16,little}),
		domain = unicode:characters_to_binary(<<Domain/binary,0>>, latin1, {utf16,little}),
		password = unicode:characters_to_binary(<<Password/binary, 0>>, latin1, {utf16,little}),
		cookie = <<Cookie/binary, 16#0d, 16#0a>>
	}),
	send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Redir}),

	{ok, Deact} = rdpp:encode_sharecontrol(#ts_deactivate{channel = Us, shareid = ShareId}),
	send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Deact}),
	ssl:close(SslSock),
	{stop, normal, D};

run_ui({fp_pdu, #fp_pdu{contents = Evts}}, D = #data{uis = Uis}) ->
	lists:foreach(fun(Evt) ->
		lists:foreach(fun(Ui) ->
			gen_fsm:send_event(Ui, {input, self(), Evt})
		end, Uis)
	end, Evts),
	{next_state, run_ui, D};

run_ui({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, D = #data{mcs = #mcs_state{them = Them, iochan = IoChan}, shareid = ShareId, uis = Uis}) ->
	case rdpp:decode_sharecontrol(RdpData) of
		{ok, #ts_sharedata{shareid = ShareId, data = #ts_input{events = Evts}}} ->
			lists:foreach(fun(Evt) ->
				lists:foreach(fun(Ui) ->
					gen_fsm:send_event(Ui, {input, self(), Evt})
				end, Uis)
			end, Evts),
			{next_state, run_ui, D};

		{ok, #ts_sharedata{} = SD} ->
			error_logger:info_report(["frontend rx: ", rdpp:pretty_print(SD)]),
			{next_state, run_ui, D}
	end;

run_ui({x224_pdu, #x224_dr{}}, D = #data{sslsock = SslSock}) ->
	ssl:close(SslSock),
	{stop, normal, D}.

wait_proxy({data, Bin}, #data{queue = Queue} = Data) ->
	{next_state, wait_proxy, Data#data{queue = Queue ++ [Bin]}};

wait_proxy({backend_ready, Backend, Backsock, TheirCC}, #data{queue = Queue, backend = Backend, x224 = #x224_state{them = ThemRef}, sock = Sock} = Data) ->
	io:format("frontend send cc: ~s\n", [x224:pretty_print(TheirCC)]),
	{ok, RespData} = x224:encode(TheirCC),
	{ok, Packet} = tpkt:encode(RespData),
	gen_tcp:send(Sock, Packet),

	inet:setopts(Sock, [{packet, raw}]),
	{ok, SslSock} = ssl:ssl_accept(Sock, [{certfile, "etc/cert.pem"}, {keyfile, "etc/key.pem"}]),
	ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),
	lists:foreach(fun(Bin) ->
		ssl:send(Backsock, Bin)
		%gen_fsm:send_event(Backend, {frontend_data, self(), Bin})
	end, Queue),
	{next_state, proxy, Data#data{queue = [], backsock = Backsock, sslsock = SslSock}}.

proxy({data, Bin}, #data{sslsock = SslSock, backsock = Backsock, backend = Backend} = Data) ->
	ssl:send(Backsock, Bin),
	%gen_fsm:send_event(Backend, {frontend_data, self(), Bin}),
	{next_state, proxy, Data};

proxy({backend_data, Backend, Bin}, #data{sslsock = SslSock, backend = Backend} = Data) ->
	ssl:send(SslSock, Bin),
	{next_state, proxy, Data}.

queue_remainder(Sock, Bin) when byte_size(Bin) > 0 ->
	self() ! {tcp, Sock, Bin};
queue_remainder(_, _) -> ok.

debug_print_data(<<>>) -> ok;
debug_print_data(Bin) ->
	case rdpp:decode_connseq(Bin) of
		{ok, {fp_pdu, Pdu}, Rem} ->
			%error_logger:info_report(["frontend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
			debug_print_data(Rem);
		{ok, {x224_pdu, Pdu}, Rem} ->
			error_logger:info_report(["frontend rx x224:\n", x224:pretty_print(Pdu)]),
			debug_print_data(Rem);
		{ok, {mcs_pdu, Pdu = #mcs_data{data = RdpData, channel = Chan}}, Rem} ->
			case rdpp:decode_basic(RdpData) of
				{ok, Rec} ->
					error_logger:info_report(["frontend rx rdp_basic:\n", rdpp:pretty_print(Rec)]);
				_ ->
					case rdpp:decode_sharecontrol(RdpData) of
						{ok, Rec} ->
							error_logger:info_report(["frontend rx rdp_sharecontrol\n", rdpp:pretty_print(Rec)]);
						_ ->
							error_logger:info_report(["frontend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]])
					end
			end,
			debug_print_data(Rem);
		{ok, {mcs_pdu, McsCi = #mcs_ci{}}, Rem} ->
			{ok, Tsuds} = tsud:decode(McsCi#mcs_ci.data),
			error_logger:info_report(["frontend rx ci with tsuds: ", tsud:pretty_print(Tsuds)]),
			debug_print_data(Rem);
		{ok, {mcs_pdu, Pdu}, Rem} ->
			error_logger:info_report(["frontend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]]),
			debug_print_data(Rem);
		_ -> ok
	end.

%% @private
handle_info({tcp, Sock, Bin}, State, #data{sock = Sock} = Data)
		when (State =:= initiation) or (State =:= mcs_connect) ->
	% we have to use decode_connseq here to avoid ambiguity in the asn.1 for
	% the mcs_ci
	case rdpp:decode_connseq(Bin) of
		{ok, Evt, Rem} ->
			queue_remainder(Sock, Rem),
			?MODULE:State(Evt, Data);
		{error, Reason} ->
			error_logger:info_report([{rdpp_decode_fail, Reason}]),
			{next_state, State, Data}
	end;
handle_info({tcp, Sock, Bin}, State, #data{sock = Sock} = Data) ->
	case rdpp:decode_server(Bin) of
		{ok, Evt, Rem} ->
			queue_remainder(Sock, Rem),
			?MODULE:State(Evt, Data);
		{error, Reason} ->
			error_logger:info_report([{rdpp_decode_fail, Reason}]),
			{next_state, State, Data}
	end;

handle_info({ssl, SslSock, Bin}, State, #data{sslsock = SslSock} = Data)
		when (State =:= proxy) orelse (State =:= wait_proxy) ->
	debug_print_data(Bin),
	case rdpp:decode_server(Bin) of
		{ok, {mcs_pdu, McsData = #mcs_data{data = RdpData0}}, Rem} ->
			case rdpp:decode_basic(RdpData0) of
				{ok, TsInfo0 = #ts_info{}} ->
					#data{session = #session{user = User, password = Password, domain = Domain}} = Data,
					TsInfo1 = TsInfo0#ts_info{flags = [autologon, unicode | TsInfo0#ts_info.flags]},
					Unicode = lists:member(unicode, TsInfo1#ts_info.flags),
					TsInfo2 = TsInfo1#ts_info{
						domain = if
							Unicode -> unicode:characters_to_binary(<<Domain/binary,0>>, latin1, {utf16, little});
							true -> <<Domain/binary, 0>> end,
						username = if
							Unicode -> unicode:characters_to_binary(<<User/binary,0>>, latin1, {utf16, little});
							true -> <<User/binary, 0>> end,
						password = if
							Unicode -> unicode:characters_to_binary(<<Password/binary,0>>, latin1, {utf16, little});
							true -> <<Password/binary, 0>> end
						},
					io:format("rewriting ts_info: ~s\n", [rdpp:pretty_print(TsInfo2)]),
					{ok, RdpData1} = rdpp:encode_basic(TsInfo2),
					{ok, McsOutBin} = mcsgcc:encode_dpdu(McsData#mcs_data{data = RdpData1}),
					{ok, X224OutBin} = x224:encode(#x224_dt{data = McsOutBin}),
					{ok, OutBin} = tpkt:encode(X224OutBin),
					?MODULE:State({data, <<OutBin/binary, Rem/binary>>}, Data);
				_ ->
					?MODULE:State({data, Bin}, Data)
			end;
		_ ->
			?MODULE:State({data, Bin}, Data)
	end;

handle_info({ssl, SslSock, Bin}, State, #data{sock = Sock, sslsock = SslSock} = Data) ->
	handle_info({tcp, Sock, Bin}, State, Data);

handle_info({ssl_closed, Sock}, State, #data{sock = Sock} = Data) ->
	{stop, normal, Data};

handle_info({tcp_closed, Sock}, State, #data{sock = Sock} = Data) ->
	{stop, normal, Data};
	%?MODULE:State(disconnect, Data);

handle_info(_Msg, State, Data) ->
	{next_state, State, Data}.

%% @private
terminate(_Reason, _State, _Data) ->
	ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
	{ok, State}.

maybe([], Args) -> error(no_return);
maybe([Fun | Rest], Args) ->
	case apply(Fun, Args) of
		{continue, NewArgs} ->
			maybe(Rest, NewArgs);
		{return, Value} ->
			Value
	end.
