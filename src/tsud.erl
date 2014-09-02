%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(tsud).

-include("tsud.hrl").

%-export([encode/1, decode/1, pretty_print/1]).
-export([encode/1, decode/1, pretty_print/1]).

-export([decode_core/1, decode_cluster/1, decode_security/1, decode_net/1, decode_svr_core/1, decode_svr_net/1, decode_svr_security/1, decode_monitor/1, decode_msgchannel/1, decode_monitor_ex/1, decode_multitransport/1, decode_svr_msgchannel/1, decode_svr_multitransport/1]).
-export([encode_core/1, encode_cluster/1, encode_security/1, encode_net/1]).

-define(pp(Rec),
pretty_print(Rec, N) ->
	N = record_info(size, Rec) - 1,
	record_info(fields, Rec)).

pretty_print(Record) ->
	io_lib_pretty:print(Record, fun pretty_print/2).
?pp(tsud_core);
?pp(tsud_security);
?pp(tsud_cluster);
?pp(tsud_net);
?pp(tsud_net_channel);
?pp(tsud_monitor);
?pp(tsud_monitor_def);
?pp(tsud_msgchannel);
?pp(tsud_multitransport);
?pp(tsud_monitor_ex);
?pp(tsud_monitor_ex_attr);
?pp(tsud_unknown);
?pp(tsud_svr_net);
?pp(tsud_svr_core);
?pp(tsud_svr_security);
?pp(tsud_svr_msgchannel);
?pp(tsud_svr_multitransport);
pretty_print(_, _) ->
	no.

-define(CS_CORE, 16#c001).
-define(CS_SECURITY, 16#c002).
-define(CS_NET, 16#c003).
-define(CS_CLUSTER, 16#c004).
-define(CS_MONITOR, 16#c005).
-define(CS_MCS_MSGCHANNEL, 16#c006).
-define(CS_MONITOR_EX, 16#c008).
-define(CS_MULTITRANSPORT, 16#c00a).

-define(SC_CORE, 16#0c01).
-define(SC_SECURITY, 16#0c02).
-define(SC_NET, 16#0c03).
-define(SC_MCS_MSGCHANNEL, 16#0c04).
-define(SC_MULTITRANSPORT, 16#0c08).

decode(Bin) ->
	case Bin of
		<<>> ->
			{ok, []};

		<<TypeN:16/little, Length:16/little, Rest/binary>> ->
			DataLength = Length - 4,
			<<Data:DataLength/binary-unit:8, Rem/binary>> = Rest,
			{ok, Others} = decode(Rem),
			Type = case TypeN of
				?CS_CORE -> decode_core;
				?CS_SECURITY -> decode_security;
				?CS_CLUSTER -> decode_cluster;
				?CS_NET -> decode_net;
				?CS_MONITOR -> decode_monitor;
				?CS_MCS_MSGCHANNEL -> decode_msgchannel;
				?CS_MONITOR_EX -> decode_monitor_ex;
				?CS_MULTITRANSPORT -> decode_multitransport;
				?SC_CORE -> decode_svr_core;
				?SC_NET -> decode_svr_net;
				?SC_SECURITY -> decode_svr_security;
				?SC_MCS_MSGCHANNEL -> decode_svr_msgchannel;
				?SC_MULTITRANSPORT -> decode_svr_multitransport;
				_ -> unknown
			end,
			if Type =:= unknown ->
				{ok, [#tsud_unknown{type = TypeN, data = Data} | Others]};
			true ->
				{ok, [?MODULE:Type(Data) | Others]}
			end;

		_ ->
			{error, bad_tsud}
	end.

encode(#tsud_core{} = Rec) -> {ok, encode_core(Rec)};
encode(#tsud_security{} = Rec) -> {ok, encode_security(Rec)};
encode(#tsud_cluster{} = Rec) -> {ok, encode_cluster(Rec)};
encode(#tsud_net{} = Rec) -> {ok, encode_net(Rec)};
encode(#tsud_svr_core{} = Rec) -> {ok, encode_svr_core(Rec)};
encode(#tsud_svr_security{} = Rec) -> {ok, encode_svr_security(Rec)};
encode(#tsud_svr_net{} = Rec) -> {ok, encode_svr_net(Rec)};
encode(#tsud_svr_msgchannel{} = Rec) -> {ok, encode_svr_msgchannel(Rec)};
encode(#tsud_svr_multitransport{} = Rec) -> {ok, encode_svr_multitransport(Rec)};
encode(_) -> {error, bad_record}.

encode_tsud(Type, Data) ->
	Len = byte_size(Data) + 4,
	<<Type:16/little, Len:16/little, Data/binary>>.

decode_svr_core(Bin) ->
	<<VerPack:32/little, Rest/binary>> = Bin,
	<<Major:16/big, Minor:16/big>> = <<VerPack:32/big>>,

	case Rest of
		<<Req:32/little, Caps:32/little>> ->
			Prots = rdpp:decode_protocol_flags(Req),

			<<_:30, DynamicDST:1, EdgeActions:1>> = <<Caps:32/big>>,
			CapFlags = if DynamicDST == 1 -> [dynamic_dst]; true -> [] end ++
					   if EdgeActions == 1 -> [edge_actions]; true -> [] end,
			#tsud_svr_core{version = [Major, Minor], requested=Prots, capabilities=CapFlags};
		_ ->
			#tsud_svr_core{version = [Major, Minor]}
	end.

encode_svr_core(#tsud_svr_core{version = [Major,Minor], requested=Prots, capabilities=CapFlags}) ->
	<<Ver:32/big>> = <<Major:16/big, Minor:16/big>>,

	Requested = rdpp:encode_protocol_flags(Prots),

	DynamicDST = case lists:member(dynamic_dst, CapFlags) of true -> 1; _ -> 0 end,
	EdgeActions = case lists:member(edge_actions, CapFlags) of true -> 1; _ -> 0 end,
	<<Caps:32/big>> = <<0:30, DynamicDST:1, EdgeActions:1>>,

	Inner = <<Ver:32/little, Requested:32/little, Caps:32/little>>,
	encode_tsud(?SC_CORE, Inner).

encode_svr_net(#tsud_svr_net{iochannel=IoChannel, channels=Chans}) ->
	ChanBin = lists:foldl(fun(Chan, Bin) ->
		<<Bin/binary, Chan:16/little>>
	end, <<>>, Chans),
	NChans = length(Chans),

	Rem = byte_size(ChanBin) rem 4,
	PadBytes = if Rem > 0 -> 4 - Rem; true -> 0 end,
	ChanPad = <<ChanBin/binary, 0:PadBytes/unit:8>>,

	Inner = <<IoChannel:16/little, NChans:16/little, ChanPad/binary>>,
	encode_tsud(?SC_NET, Inner).

decode_svr_net_channels(0, _) -> [];
decode_svr_net_channels(N, Bin) ->
	<<ChanId:16/little, Rest/binary>> = Bin,
	[ChanId | decode_svr_net_channels(N-1, Rest)].

decode_svr_net(Bin) ->
	<<IoChannel:16/little, ChanCount:16/little, Rest/binary>> = Bin,
	Chans = decode_svr_net_channels(ChanCount, Rest),
	#tsud_svr_net{iochannel = IoChannel, channels = Chans}.

encode_svr_security(#tsud_svr_security{method=MethodAtom, level=LevelAtom, random=ServerRandom, certificate=Cert}) ->
	Meth = case MethodAtom of
		rc4_40 -> 16#01;
		rc4_128 -> 16#02;
		rc4_56 -> 16#08;
		_ -> 0
	end,
	Level = case LevelAtom of
		low -> 16#01;
		client_compatible -> 16#02;
		high -> 16#03;
		fips -> 16#04;
		_ -> 0
	end,
	Inner = if (Meth == 0) and (Level == 0) ->
		<<Meth:32/little, Level:32/little>>;
	true ->
		RandomLen = byte_size(ServerRandom),
		CertLen = byte_size(Cert),
		<<Meth:32/little, Level:32/little, RandomLen:32/little, CertLen:32/little, ServerRandom/binary, Cert/binary>>
	end,
	encode_tsud(?SC_SECURITY, Inner).

decode_svr_security(Bin) ->
	<<Method:32/little, Level:32/little, Rest/binary>> = Bin,
	<<_:27, Fips:1, Meth:4>> = <<Method:32/big>>,
	MethodAtom = case Meth of
		16#00 -> none;
		16#01 -> rc4_40;
		16#02 -> rc4_128;
		16#08 -> rc4_56;
		_ -> unknown
	end,
	LevelAtom = case Level of
		16#00 -> none;
		16#01 -> low;
		16#02 -> client_compatible;
		16#03 -> high;
		16#04 -> fips;
		_ -> unknown
	end,
	if (Method == 0) and (Level == 0) ->
		#tsud_svr_security{method = MethodAtom, level = LevelAtom};
	true ->
		<<RandomLen:32/little, CertLen:32/little, Rest2/binary>> = Rest,
		<<ServerRandom:RandomLen/binary-unit:8, Cert:CertLen/binary-unit:8>> = Rest2,
		#tsud_svr_security{method = MethodAtom, level = LevelAtom, random = ServerRandom, certificate = Cert}
	end.

encode_svr_msgchannel(#tsud_svr_msgchannel{channel = Chan}) ->
	encode_tsud(?SC_MCS_MSGCHANNEL, <<Chan:16/little>>).

decode_svr_msgchannel(Bin) ->
	<<Chan:16/little>> = Bin,
	#tsud_svr_msgchannel{channel = Chan}.

zerobin_to_string(Bin) ->
	[First|_] = binary:split(Bin, <<0>>),
	binary_to_list(First).

decode_net_channels(<<>>) -> [];
decode_net_channels(Bin) ->
	<<Name:8/binary, Options:32/little, Rest/binary>> = Bin,
	<<Init:1, EncryptRdp:1, EncryptSC:1, EncryptCS:1, HighPri:1, MedPri:1, LowPri:1, _:1, CompressRdp:1, Compress:1, ShowProtocol:1, Persistent:1, _/bitstring>> = <<Options:32/big>>,
	Pri = if HighPri == 1 -> high; MedPri == 1 -> medium; true -> low end,
	Flags = if Init == 1 -> [init]; true -> [] end ++
			if EncryptRdp == 1 -> [encrypt_rdp]; true -> [] end ++
			if EncryptSC == 1 -> [encrypt_sc]; true -> [] end ++
			if EncryptCS == 1 -> [encrypt_cs]; true -> [] end ++
			if CompressRdp == 1 -> [compress_rdp]; true -> [] end ++
			if Compress == 1 -> [compress]; true -> [] end ++
			if ShowProtocol == 1 -> [show_protocol]; true -> [] end ++
			if Persistent == 1 -> [persistent]; true -> [] end,
	Chan = #tsud_net_channel{name = zerobin_to_string(Name), priority = Pri, flags = Flags},
	[Chan | decode_net_channels(Rest)].

decode_net(Data) ->
	<<Count:32/little, Rest/binary>> = Data,
	Chans = decode_net_channels(Rest),
	Count = length(Chans),
	#tsud_net{channels = Chans}.

encode_net(Rec) ->
	encode_tsud(?CS_NET, <<>>).

decode_cluster(Data) ->
	<<Flags:32/little, SessionId:32/little>> = Data,
	<<_:25, Smartcard:1, Version:4, ValidSession:1, Supported:1>> = <<Flags:32/big>>,
	FlagAtoms = if Smartcard == 1 -> [smartcard]; true -> [] end ++
				if Supported == 1 -> [supported]; true -> [] end,
	#tsud_cluster{version = Version+1, flags = FlagAtoms, sessionid = if ValidSession == 1 -> SessionId; true -> none end}.

encode_cluster(#tsud_cluster{version = Ver, flags = Flags, sessionid = SessionId}) ->
	Smartcard = case lists:member(smartcard, Flags) of true -> 1; _ -> 0 end,
	Supported = case lists:member(supported, Flags) of true -> 1; _ -> 0 end,
	ValidSession = case SessionId of none -> 0; _ -> 1 end,
	Version = Ver - 1,
	<<FlagBits:32/big>> = <<0:25, Smartcard:1, Version:4, ValidSession:1, Supported:1>>,

	SessionIdNum = case SessionId of none -> 0; _ -> SessionId end,
	encode_tsud(?CS_CLUSTER, <<FlagBits:32/little, SessionIdNum:32/little>>).

decode_security(Data) ->
	<<Methods:32/little, ExtMethods:32/little>> = Data,
	<<_:27, Fips:1, Enc56:1, _:1, Enc128:1, Enc40:1>> = <<Methods:32/big>>,
	MethodAtoms = if Fips == 1 -> [fips]; true -> [] end ++ if Enc56 == 1 -> ['rc4_56']; true -> [] end ++ if Enc128 == 1 -> ['rc4_128']; true -> [] end ++ if Enc40 == 1 -> ['rc4_40']; true -> [] end,
	#tsud_security{methods = MethodAtoms}.

encode_security(#tsud_security{methods = Methods}) ->
	Fips = case lists:member(fips, Methods) of true -> 1; _ -> 0 end,
	Enc56 = case lists:member(rc4_56, Methods) of true -> 1; _ -> 0 end,
	Enc128 = case lists:member(rc4_128, Methods) of true -> 1; _ -> 0 end,
	Enc40 = case lists:member(rc4_40, Methods) of true -> 1; _ -> 0 end,
	<<MethodFlags:32/big>> = <<0:27, Fips:1, Enc56:1, 0:1, Enc128:1, Enc40:1>>,
	encode_tsud(?CS_SECURITY, <<MethodFlags:32/little, 0:32>>).

zero_pad(Bin, Len) when is_list(Bin) ->
	zero_pad(list_to_binary(Bin), Len);
zero_pad(Bin, Len) ->
	Rem = Len - byte_size(Bin),
	<<Bin/binary, 0:Rem/unit:8>>.

decode_monitor_defs(<<>>) -> [];
decode_monitor_defs(Bin) ->
	<<Left:32/little-signed, Top:32/little-signed, Right:32/little-signed, Bottom:32/little-signed, Flags:32/little, Rest/binary>> = Bin,
	<<_:31, Primary:1>> = <<Flags:32/big>>,
	FlagAtoms = if Primary == 1 -> [primary]; true -> [] end,
	[#tsud_monitor_def{left = Left, top = Top, right = Right, bottom = Bottom, flags = FlagAtoms} | decode_monitor_defs(Rest)].

decode_monitor(Data) ->
	<<_Flags:32/little, Count:32/little, MonitorBins/binary>> = Data,
	Monitors = decode_monitor_defs(MonitorBins),
	Count = length(Monitors),
	#tsud_monitor{monitors = Monitors}.

decode_msgchannel(Data) ->
	#tsud_msgchannel{}.

decode_monitor_attrs(<<>>) -> [];
decode_monitor_attrs(Bin) ->
	<<PhysWidth:32/little, PhysHeight:32/little, Angle:32/little, DesktopScale:32/little, DeviceScale:32/little, Rest/binary>> = Bin,
	case Angle of
		0 -> ok; 90 -> ok; 180 -> ok; 270 -> ok;
		_ -> error({bad_monitor_ex_angle, Angle})
	end,
	[#tsud_monitor_ex_attr{phys_width = PhysWidth, phys_height = PhysHeight, angle = Angle, desktop_scale = DesktopScale, device_scale = DeviceScale} | decode_monitor_attrs(Rest)].

decode_monitor_ex(Data) ->
	<<_Flags:32/little, ElemSize:32/little, Count:32/little, MonitorBins/binary>> = Data,
	ElemSize = 20,
	Monitors = decode_monitor_attrs(MonitorBins),
	Count = length(Monitors),
	#tsud_monitor_ex{monitors = Monitors}.

decode_multitransport(Data) ->
	<<Flags:32/little>> = Data,
	<<_:23, UdpPref:1, _:5, UdpFecLossy:1, _:1, UdpFec:1>> = <<Flags:32/big>>,
	FlagAtoms = if UdpPref == 1 -> [udp_preferred]; true -> [] end ++
				if UdpFecLossy == 1 -> [udp_fec_lossy]; true -> [] end ++
				if UdpFec == 1 -> [udp_fec]; true -> [] end,
	#tsud_multitransport{flags = FlagAtoms}.

decode_svr_multitransport(Data) ->
	<<Flags:32/little>> = Data,
	<<_:23, UdpPref:1, _:5, UdpFecLossy:1, _:1, UdpFec:1>> = <<Flags:32/big>>,
	FlagAtoms = if UdpPref == 1 -> [udp_preferred]; true -> [] end ++
				if UdpFecLossy == 1 -> [udp_fec_lossy]; true -> [] end ++
				if UdpFec == 1 -> [udp_fec]; true -> [] end,
	#tsud_svr_multitransport{flags = FlagAtoms}.

encode_svr_multitransport(#tsud_svr_multitransport{flags = Flags}) ->
	UdpPref = case lists:member(udp_preferred, Flags) of true -> 1; _ -> 0 end,
	UdpFecLossy = case lists:member(udp_fec_lossy, Flags) of true -> 1; _ -> 0 end,
	UdpFec = case lists:member(udp_fec, Flags) of true -> 1; _ -> 0 end,

	<<FlagField:32/big>> = <<0:23, UdpPref:1, 0:5, UdpFecLossy:1, 0:1, UdpFec:1>>,
	encode_tsud(?SC_MULTITRANSPORT, <<FlagField:32/little>>).

encode_core(Rec) ->
	#tsud_core{version=[Major, Minor], width=Width, height=Height, sas=SAS, kbd_layout=KbdLayout, client_build=ClientBuild, client_name=ClientName, kbd_type=KbdType, kbd_sub_type=KbdSubType, kbd_fun_keys=KbdFunKeys, color=Color, colors=Colors, capabilities=Caps, selected=Selected, conn_type=ConnType} = Rec,

	<<Ver:32/big>> = <<Major:16/big, Minor:16/big>>,
	Depth = case Color of
		'4bpp' -> 16#04;
		'8bpp' -> 16#08;
		'15bpp' -> 16#0f;
		'16bpp' -> 16#10;
		'24bpp' -> 16#18;
		_ -> 0
	end,

	Support32 = case lists:member('32bpp', Colors) of true -> 1; _ -> 0 end,
	Support15 = case lists:member('15bpp', Colors) of true -> 1; _ -> 0 end,
	Support16 = case lists:member('16bpp', Colors) of true -> 1; _ -> 0 end,
	Support24 = case lists:member('24bpp', Colors) of true -> 1; _ -> 0 end,
	<<Supported:16/big>> = <<0:12, Support32:1, Support15:1, Support16:1, Support24:1>>,

	Prots = rdpp:encode_protocol_flags(Selected),

	{ConnTyp, ConnTypeValid} = case ConnType of
		modem -> {16#01, 1};
		broadband_low -> {16#02, 1};
		satellite -> {16#03, 1};
		broadband_high -> {16#04, 1};
		wan -> {16#05, 1};
		lan -> {16#06, 1};
		auto -> {16#07, 1};
		_ -> {0, 0}
	end,

	DynamicDST = case lists:member(dynamic_dst, Caps) of true -> 1; _ -> 0 end,
	DynVCGFX = case lists:member(dynvc_gfx, Caps) of true -> 1; _ -> 0 end,
	NetCharAuto = case lists:member(netchar_autodetect, Caps) of true -> 1; _ -> 0 end,
	MonitorLayout = case lists:member(monitor_layout, Caps) of true -> 1; _ -> 0 end,
	StrongKeys = case lists:member(strongkeys, Caps) of true -> 1; _ -> 0 end,
	StatusInfo = case lists:member(statusinfo, Caps) of true -> 1; _ -> 0 end,
	Want32 = case lists:member(want_32bpp, Caps) of true -> 1; _ -> 0 end,
	ErrInfo = case lists:member(errinfo, Caps) of true -> 1; _ -> 0 end,
	<<CapFlags:16/big>> = <<0:6, DynamicDST:1, DynVCGFX:1, NetCharAuto:1, MonitorLayout:1, ConnTypeValid:1, 0:1, StrongKeys:1, StatusInfo:1, Want32:1, ErrInfo:1>>,

	ClientNamePad = zero_pad(ClientName, 32),
	ImeName = <<0:64/unit:8>>,
	ClientProductId = zero_pad(<<"1">>, 64),

	Inner = <<Ver:32/little, Width:16/little, Height:16/little, 0:16, SAS:16/little, KbdLayout:32/little, ClientBuild:32/little, ClientNamePad:32/binary-unit:8, KbdType:32/little, KbdSubType:32/little, KbdFunKeys:32/little, ImeName:64/binary-unit:8, 0:16, 0:16, 0:32, Depth:16/little, Supported:16/little, CapFlags:16/little, ClientProductId:64/binary-unit:8, ConnTyp:8, 0:8, Prots:32/little>>,
	encode_tsud(?CS_CORE, Inner).

decode_core(Data) ->
	<<Ver:32/little, Width:16/little, Height:16/little, OldDepth:16/little, SAS:16/little, KbdLayout:32/little, ClientBuild:32/little, ClientName:32/binary-unit:8, KbdType:32/little, KbdSubType:32/little, KbdFunKeys:32/little, ImeName:64/binary-unit:8, Rest/binary>> = Data,
	<<Major:16/big, Minor:16/big>> = <<Ver:32/big>>,
	SoFar = #tsud_core{version = [Major, Minor], width = Width, height = Height, sas = SAS, kbd_layout = KbdLayout, client_build = ClientBuild, client_name = ClientName, kbd_type = KbdType, kbd_sub_type = KbdSubType, kbd_fun_keys = KbdFunKeys},

	case Rest of
		<<_MidDepth:16/little, _ProductID:16/little, _Serial:32/little, NewDepth:16/little, SupportedDepths:16/little, CapFlags:16/little, ClientProductID:64/binary-unit:8, ConnType:8, _:8, Selected:32/little, _/binary>> ->

			Depth = case NewDepth of
				16#04 -> '4bpp';
				16#08 -> '8bpp';
				16#0f -> '15bpp';
				16#10 -> '16bpp';
				16#18 -> '24bpp';
				_ -> unknown
			end,

			<<_:12, Support32:1, Support15:1, Support16:1, Support24:1>> = <<SupportedDepths:16/big>>,
			Supported = if Support32 == 1 -> ['32bpp']; true -> [] end ++ if Support15 == 1 -> ['15bpp']; true -> [] end ++ if Support16 == 1 -> ['16bpp']; true -> [] end ++ if Support24 == 1 -> ['24bpp']; true -> [] end,

			Prots = rdpp:decode_protocol_flags(Selected),

			<<_:6, DynamicDST:1, DynVCGFX:1, NetCharAuto:1, MonitorLayout:1, ConnTypeValid:1, _:1, StrongKeys:1, StatusInfo:1, Want32:1, ErrInfo:1>> = <<CapFlags:16/big>>,
			Caps = if DynamicDST == 1 -> [dynamic_dst]; true -> [] end ++
				   if DynVCGFX == 1 -> [dynvc_gfx]; true -> [] end ++
				   if NetCharAuto == 1 -> [netchar_autodetect]; true -> [] end ++
				   if MonitorLayout == 1 -> [monitor_layout]; true -> [] end ++
				   if StrongKeys == 1 -> [strongkeys]; true -> [] end ++
				   if StatusInfo == 1 -> [statusinfo]; true -> [] end ++
				   if Want32 == 1 -> [want_32bpp]; true -> [] end ++
				   if ErrInfo == 1 -> [errinfo]; true -> [] end,

			ConnTypeAtom = if ConnTypeValid == 1 ->
				case ConnType of
					16#01 -> modem;
					16#02 -> broadband_low;
					16#03 -> satellite;
					16#04 -> broadband_high;
					16#05 -> wan;
					16#06 -> lan;
					16#07 -> auto;
					_ -> unknown
				end;
			true -> unknown
			end,

			SoFar#tsud_core{color = Depth, capabilities = Caps, selected = Prots, conn_type = ConnTypeAtom, colors = Supported};

		<<NewDepth:16/little, _/binary>> ->
			Depth = case NewDepth of
				16#ca00 -> '4bpp';
				16#ca01 -> '8bpp';
				16#ca02 -> '16bpp_555';
				16#ca03 -> '16bpp_565';
				16#ca04 -> '24bpp';
				_ -> unknown
			end,
			SoFar#tsud_core{color = Depth};

		_ ->
			Depth = case OldDepth of
				16#ca00 -> '4bpp';
				16#ca01 -> '8bpp';
				_ -> unknown
			end,
			SoFar#tsud_core{color = Depth}
	end.

