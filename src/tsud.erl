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

-export([decode_core/1, decode_cluster/1, decode_security/1, decode_net/1, decode_svr_core/1, decode_svr_net/1, decode_svr_security/1]).
-export([encode_core/1, encode_cluster/1, encode_security/1, encode_net/1]).

pretty_print(Record) ->
	io_lib_pretty:print(Record, fun pretty_print/2).
pretty_print(tsud_core, N) ->
	N = record_info(size, tsud_core) - 1,
	record_info(fields, tsud_core);
pretty_print(tsud_security, N) ->
	N = record_info(size, tsud_security) - 1,
	record_info(fields, tsud_security);
pretty_print(tsud_cluster, N) ->
	N = record_info(size, tsud_cluster) - 1,
	record_info(fields, tsud_cluster);
pretty_print(tsud_net, N) ->
	N = record_info(size, tsud_net) - 1,
	record_info(fields, tsud_net);
pretty_print(tsud_net_channel, N) ->
	N = record_info(size, tsud_net_channel) - 1,
	record_info(fields, tsud_net_channel);
pretty_print(tsud_svr_net, N) ->
	N = record_info(size, tsud_svr_net) - 1,
	record_info(fields, tsud_svr_net);
pretty_print(tsud_svr_core, N) ->
	N = record_info(size, tsud_svr_core) - 1,
	record_info(fields, tsud_svr_core);
pretty_print(tsud_svr_security, N) ->
	N = record_info(size, tsud_svr_security) - 1,
	record_info(fields, tsud_svr_security);
%pretty_print(x224_cr, N) ->
%	N = record_info(size, x224_cr) - 1,
%	record_info(fields, x224_cr);
pretty_print(_, _) ->
	no.

-define(CS_CORE, 16#c001).
-define(CS_SECURITY, 16#c002).
-define(CS_NET, 16#c003).
-define(CS_CLUSTER, 16#c004).

-define(SC_CORE, 16#0c01).
-define(SC_SECURITY, 16#0c02).
-define(SC_NET, 16#0c03).

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
				?SC_CORE -> decode_svr_core;
				?SC_NET -> decode_svr_net;
				?SC_SECURITY -> decode_svr_security;
				_ -> unknown
			end,
			if Type =:= unknown ->
				{ok, Others};
			true ->
				{ok, [?MODULE:Type(Data)|Others]}
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
encode(_) -> {error, bad_record}.

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
	Len = byte_size(Inner) + 4,
	<<?SC_CORE:16/little, Len:16/little, Inner/binary>>.

encode_svr_net(#tsud_svr_net{iochannel=IoChannel, channels=Chans}) ->
	ChanBin = lists:foldl(fun(Chan, Bin) ->
		<<Bin/binary, Chan:16/little>>
	end, <<>>, Chans),
	NChans = length(Chans),

	Inner = <<IoChannel:16/little, NChans:16/little, ChanBin/binary>>,
	Len = byte_size(Inner) + 4,
	<<?SC_NET:16/little, Len:16/little, Inner/binary>>.

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
	Len = byte_size(Inner) + 4,
	<<?SC_SECURITY:16/little, Len:16/little, Inner/binary>>.

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
	Chan = #tsud_net_channel{name = binary_to_list(Name), priority = Pri, flags = Flags},
	[Chan | decode_net_channels(Rest)].

decode_net(Data) ->
	<<Count:32/little, Rest/binary>> = Data,
	Chans = decode_net_channels(Rest),
	Count = length(Chans),
	#tsud_net{channels = Chans}.

encode_net(Rec) ->
	<<?CS_NET:16/little, 0:16>>.

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
	<<?CS_CLUSTER:16/little, 12:16/little, FlagBits:32/little, SessionIdNum:32/little>>.

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
	<<?CS_SECURITY:16/little, 12:16/little, MethodFlags:32/little, 0:32>>.

zero_pad(Bin, Len) when is_list(Bin) ->
	zero_pad(list_to_binary(Bin), Len);
zero_pad(Bin, Len) ->
	Rem = Len - byte_size(Bin),
	<<Bin/binary, 0:Rem/unit:8>>.

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
	Len = byte_size(Inner) + 4,
	<<?CS_CORE:16/little, Len:16/little, Inner/binary>>.

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

