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

-export([start_link/1]).
-export([wait_control/2, initiation/2, mcs_connect/2, mcs_attach_user/2, mcs_chans/2, rdp_clientinfo/2, rdp_capex/2, init_finalize/2, clicky/2, clicky_highlight/2, proxy/2, wait_proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Sock :: term()) -> {ok, pid()}.
start_link(Sock) ->
	gen_fsm:start_link(?MODULE, [Sock], []).

-record(x224_state, {us=none, them=none}).
-record(mcs_state, {us=none, them=none, iochan=none, msgchan=none, chans=[]}).
-record(data, {sock, sslsock=none, backsock=none, chansavail=[], backend=none, queue=[], waitchans=[], tsud_core={}, tsuds=[], caps=[], askedfor=[], shareid=0, x224=#x224_state{}, mcs=#mcs_state{}}).

send_dpdu(SslSock, McsPkt) ->
	{ok, McsData} = mcsgcc:encode_dpdu(McsPkt),
	{ok, DtData} = x224:encode(#x224_dt{data = McsData}),
	{ok, Packet} = tpkt:encode(DtData),
	ok = ssl:send(SslSock, Packet).

send_update(Data = #data{sslsock = SslSock, caps = Caps}, TsUpdate) ->
	#ts_cap_general{flags = Flags} = lists:keyfind(ts_cap_general, 1, Caps),
	case lists:member(fastpath, Flags) of
		true ->
			Bin = fastpath:encode_output(#fp_pdu{flags=[], contents=[TsUpdate]}),
			ok = ssl:send(SslSock, Bin);
		_ ->
			#data{shareid = ShareId, mcs = #mcs_state{us = Us, iochan = IoChan}} = Data,
			{ok, Bin} = rdpp:encode_sharecontrol(#ts_sharedata{channel = Us, shareid = ShareId, data = TsUpdate}),
			send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Bin})
	end.

%% @private
init([Sock]) ->
	process_flag(trap_exit, true),
	random:seed(erlang:now()),
	{ok, wait_control, #data{sock = Sock, chansavail=lists:seq(1002,1002+35)}}.

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

%% @doc Waiting for control of the socket to be given by frontend_listener
wait_control(control_given, #data{sock = Sock} = Data) ->
	inet:setopts(Sock, [{packet, tpkt}, {active, once}, {nodelay, true}]),
	{next_state, initiation, Data}.

initiation({x224_pdu, #x224_cr{class = 0, dst = 0} = Pkt}, #data{sock = Sock, x224 = X224} = Data) ->
	#x224_cr{src = ThemRef, rdp_cookie = Cookie, rdp_protocols = Protos} = Pkt,

	UsRef = 100 + random:uniform(100),
	error_logger:info_report([{them_ref, ThemRef}, {us_ref, UsRef}]),
	NewX224 = X224#x224_state{them = ThemRef, us = UsRef},
	NewData = Data#data{x224 = NewX224, askedfor=Protos},
	HasSsl = lists:member(ssl, Protos),

	if HasSsl ->
		Resp = #x224_cc{src = UsRef, dst = ThemRef, rdp_selected = [ssl], rdp_flags = [extdata]},
		{ok, RespData} = x224:encode(Resp),
		{ok, Packet} = tpkt:encode(RespData),
		gen_tcp:send(Sock, Packet),

		inet:setopts(Sock, [{packet, raw}]),
		{ok, SslSock} = ssl:ssl_accept(Sock, [{certfile, "etc/cert.pem"}, {keyfile, "etc/key.pem"}]),
		ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),

		%{ok, Backend} = backend:start_link(self(), "areole.cooperi.net", 3389),
		%{next_state, wait_proxy, NewData#data{sslsock = SslSock, backend = Backend}};
		case session_mgr:get(Cookie) of
			{ok, #session{host = Host, port = Port}} ->
				{ok, Backend} = backend:start_link(self(), "areole.cooperi.net", 3389),
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

			send_update(Data, #ts_update_orders{orders = [
				#ts_order_opaquerect{dest={200,200}, size={100,50}, color={255,100,100}}
				%#ts_order_line{start=[100,100], finish=[200,200], color=[255,255,255]}
			]}),

			{next_state, clicky, Data};

		{ok, #ts_sharedata{} = SD} ->
			error_logger:info_report(["finalize: ", rdpp:pretty_print(SD)]),
			{next_state, init_finalize, Data};

		Other ->
			{stop, Other, Data}
	end.

clicky({fp_pdu, #fp_pdu{contents = Evts}}, #data{sslsock = SslSock, mcs = #mcs_state{us = Us, iochan = IoChan}, shareid = ShareId} = Data) ->
	case lists:last(Evts) of
		#fp_inp_mouse{action=move, point={X,Y}} ->
			if (X > 200) and (X < 300) and (Y > 200) and (Y < 250) ->
				send_update(Data, #ts_update_orders{orders = [
					#ts_order_opaquerect{dest={200,200}, size={100,50}, color={255,230,230}}
				]}),
				{next_state, clicky_highlight, Data};
			true ->
				{next_state, clicky, Data}
			end;
		_ ->
			{next_state, clicky, Data}
	end;

clicky({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, #data{sslsock = SslSock, mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}, shareid = ShareId} = Data) ->
	case rdpp:decode_sharecontrol(RdpData) of
		{ok, #ts_sharedata{shareid = ShareId, data = #ts_input{events = Evts}}} ->
			case lists:last(Evts) of
				#ts_inpevt_mouse{action=move, point={X,Y}} ->
					if (X > 200) and (X < 300) and (Y > 200) and (Y < 250) ->
						send_update(Data, #ts_update_orders{orders = [
							#ts_order_opaquerect{dest={200,200}, size={100,50}, color={255,230,230}}
						]}),
						{next_state, clicky_highlight, Data};
					true ->
						{next_state, clicky, Data}
					end;
				_ ->
					{next_state, clicky, Data}
			end;
		{ok, #ts_sharedata{} = SD} ->
			error_logger:info_report(["clicky: ", rdpp:pretty_print(SD)]),
			{next_state, clicky, Data};

		Other ->
			{stop, Other, Data}
	end.

clicky_highlight({fp_pdu, #fp_pdu{contents = Evts}}, #data{sslsock = SslSock, mcs = #mcs_state{us = Us, iochan = IoChan}, shareid = ShareId} = Data) ->
	case lists:last(Evts) of
		#fp_inp_mouse{action=move, point={X,Y}} ->
			if (X > 200) and (X < 300) and (Y > 200) and (Y < 250) ->
				{next_state, clicky_highlight, Data};
			true ->
				send_update(Data, #ts_update_orders{orders = [
					#ts_order_opaquerect{dest={200,200}, size={100,50}, color={255,100,100}}
				]}),
				{next_state, clicky, Data}
			end;
		#fp_inp_mouse{action=down, buttons=[1], point={X,Y}} ->
			if (X > 200) and (X < 300) and (Y > 200) and (Y < 250) ->
				{ok, Cookie} = session_mgr:store(#session{host = "areole.cooperi.net", port = 3389}),
				GeneralCap = lists:keyfind(ts_cap_general, 1, Data#data.caps),
				{ok, Redir} = rdpp:encode_sharecontrol(#ts_redir{
					channel = Us,
					shareid = ShareId,
					sessionid = 100,
					flags = [logon],
					address = if GeneralCap#ts_cap_general.os =:= [other,other] ->
						unicode:characters_to_binary(<<"uqawil16-mbp",0>>, latin1, {utf16, little});
						true -> undefined end,
					%fqdn = <<"areole.cooperi.net",0>>,
					username = unicode:characters_to_binary(<<"test",0>>, latin1, {utf16,little}),
					domain = unicode:characters_to_binary(<<"COOPERI",0>>, latin1, {utf16,little}),
					password = unicode:characters_to_binary(<<"test">>, latin1, {utf16,little}),
					cookie = <<Cookie/binary, 16#0d, 16#0a>>
				}),
				send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Redir}),

				{ok, Deact} = rdpp:encode_sharecontrol(#ts_deactivate{channel = Us, shareid = ShareId}),
				send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Deact}),
				ssl:close(SslSock),
				{next_state, clicky_highlight, Data};
			true ->
				{next_state, clicky_highlight, Data}
			end;
		_ ->
			{next_state, clicky_highlight, Data}
	end;

clicky_highlight({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, #data{sslsock = SslSock, mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}, shareid = ShareId} = Data) ->
	case rdpp:decode_sharecontrol(RdpData) of
		{ok, #ts_sharedata{shareid = ShareId, data = #ts_input{events = Evts}}} ->
			case lists:last(Evts) of
				#ts_inpevt_mouse{action=move, point={X,Y}} ->
					if (X > 200) and (X < 300) and (Y > 200) and (Y < 250) ->
						{next_state, clicky_highlight, Data};
					true ->
						send_update(Data, #ts_update_orders{orders = [
							#ts_order_opaquerect{dest={200,200}, size={100,50}, color={255,100,100}}
						]}),
						{next_state, clicky, Data}
					end;
				#ts_inpevt_mouse{action=down, buttons=[1], point={X,Y}} ->
					if (X > 200) and (X < 300) and (Y > 200) and (Y < 250) ->
						{ok, Cookie} = session_mgr:store(#session{host = "areole.cooperi.net", port = 3389}),
						{ok, Redir} = rdpp:encode_sharecontrol(#ts_redir{
							channel = Us,
							shareid = ShareId,
							sessionid = 1,
							flags = [],
							username = unicode:characters_to_binary(<<"test",0>>, latin1, {utf16,little}),
							domain = unicode:characters_to_binary(<<"COOPERI",0>>, latin1, {utf16,little}),
							password = unicode:characters_to_binary(<<"test">>, latin1, {utf16,little}),
							cookie = <<Cookie/binary, 16#0d, 16#0a>>
						}),
						send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Redir}),

						%{ok, Deact} = rdpp:encode_sharecontrol(#ts_deactivate{}),
						%send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Deact}),
						%ssl:close(SslSock),
						{next_state, clicky_highlight, Data};
					true ->
						{next_state, clicky_highlight, Data}
					end;
				_ ->
					{next_state, clicky_highlight, Data}
			end;

		{ok, #ts_sharedata{} = SD} ->
			error_logger:info_report(["clicky highlight: ", rdpp:pretty_print(SD)]),
			{next_state, clicky_highlight, Data};

		Other ->
			{stop, Other, Data}
	end.


wait_proxy({data, Bin}, #data{queue = Queue} = Data) ->
	{next_state, wait_proxy, Data#data{queue = Queue ++ [Bin]}};

wait_proxy({backend_ready, Backend, Backsock}, #data{queue = Queue, backend = Backend} = Data) ->
	lists:foreach(fun(Bin) ->
		ssl:send(Backsock, Bin)
		%gen_fsm:send_event(Backend, {frontend_data, self(), Bin})
	end, Queue),
	{next_state, proxy, Data#data{queue = [], backsock = Backsock}}.

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

handle_info({ssl, SslSock, Bin}, wait_proxy, #data{sslsock = SslSock} = Data) ->
	wait_proxy({data, Bin}, Data);
handle_info({ssl, SslSock, Bin}, proxy, #data{sslsock = SslSock} = Data) ->
	case rdpp:decode_server(Bin) of
		{ok, {fp_pdu, Pdu}, _} ->
			error_logger:info_report(["frontend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
		{ok, {x224_pdu, Pdu}, _} ->
			error_logger:info_report(["frontend rx x224:\n", x224:pretty_print(Pdu)]);
		{ok, {mcs_pdu, Pdu = #mcs_data{data = RdpData, channel = Chan}}, _} ->
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
			end;
		{ok, {mcs_pdu, Pdu}, _} ->
			error_logger:info_report(["frontend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]]);
		_ -> ok
	end,
	proxy({data, Bin}, Data);

handle_info({ssl, SslSock, Bin}, State, #data{sock = Sock, sslsock = SslSock} = Data) ->
	handle_info({tcp, Sock, Bin}, State, Data);

handle_info({tcp_closed, Sock}, State, #data{sock = Sock} = Data) ->
	{stop, closed, Data};
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
