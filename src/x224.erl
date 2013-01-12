%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(x224).

-include("x224.hrl").

-export([encode/1, decode/1, pretty_print/1]).

-define(PDU_CR, 2#1110).
-define(PDU_CC, 2#1101).
-define(PDU_DR, 2#1000).
-define(PDU_AK, 2#0110).
-define(PDU_DT, 2#1111).

-define(RDP_NEGREQ, 16#01).
-define(RDP_NEGRSP, 16#02).
-define(RDP_NEGFAIL, 16#03).

pretty_print(Record) ->
	io_lib_pretty:print(Record, fun pretty_print/2).
pretty_print(x224_cr, N) ->
	N = record_info(size, x224_cr) - 1,
	record_info(fields, x224_cr);
pretty_print(x224_cc, N) ->
	N = record_info(size, x224_cc) - 1,
	record_info(fields, x224_cc);
pretty_print(x224_dt, N) ->
	N = record_info(size, x224_dt) - 1,
	record_info(fields, x224_dt);
pretty_print(x224_dr, N) ->
	N = record_info(size, x224_dr) - 1,
	record_info(fields, x224_dr);
pretty_print(_, _) ->
	no.

-spec encode(Record :: term()) -> {ok, binary()} | {error, term()}.
encode(Record) ->
	case Record of
		#x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie, rdp_protocols = Protocols} ->
			Head = <<?PDU_CR:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,
			CookiePart = if is_binary(Cookie) and not (Cookie =:= <<>>) ->
				<<Cookie/binary, 16#0d0a:16/big>>;
			is_list(Cookie) and not (Cookie =:= []) ->
				Bin = list_to_binary(Cookie),
				<<Bin/binary, 16#0d0a:16/big>>;
			true ->
				<<>>
			end,

			CredSSPEarly = case lists:member(credssp_early, Protocols) of true -> 1; _ -> 0 end,
			CredSSP = case lists:member(credssp, Protocols) of true -> 1; _ -> 0 end,
			Ssl = case lists:member(ssl, Protocols) of true -> 1; _ -> 0 end,
			<<Prots:32/big>> = <<0:28, CredSSPEarly:1, 0:1, CredSSP:1, Ssl:1>>,
			RdpPart = <<?RDP_NEGREQ:8, 0:8, 8:16/little, Prots:32/little>>,

			LI = byte_size(Head) + byte_size(CookiePart) + byte_size(RdpPart),
			{ok, <<LI:8, Head/binary, CookiePart/binary, RdpPart/binary>>};

		#x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status = error, rdp_error = Error} ->
			Head = <<?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,
			Code = case Error of
				ssl_required -> 16#01;
				ssl_not_allowed -> 16#02;
				cert_not_on_server -> 16#03;
				bad_flags -> 16#04;
				credssp_required -> 16#05;
				ssl_with_user_auth_required -> 16#06;
				_ -> 0
			end,
			RdpPart = <<?RDP_NEGFAIL:8, 0:8, 8:16/little, Code:32/little>>,

			LI = byte_size(Head) + byte_size(RdpPart),
			{ok, <<LI:8, Head/binary, RdpPart/binary>>};

		#x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status=ok, rdp_flags = Flags, rdp_selected = Protocols} ->
			Head = <<?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,

			CredSSPEarly = case lists:member(credssp_early, Protocols) of true -> 1; _ -> 0 end,
			CredSSP = case lists:member(credssp, Protocols) of true -> 1; _ -> 0 end,
			Ssl = case lists:member(ssl, Protocols) of true -> 1; _ -> 0 end,
			<<Prots:32/big>> = <<0:28, CredSSPEarly:1, 0:1, CredSSP:1, Ssl:1>>,

			DynVcGfx = case lists:member(dynvc_gfx, Flags) of true -> 1; _ -> 0 end,
			ExtData = case lists:member(extdata, Flags) of true -> 1; _ -> 0 end,
			<<Flags2:8>> = <<0:5, 0:1, DynVcGfx:1, ExtData:1>>,

			RdpPart = <<?RDP_NEGRSP:8, Flags2:8, 8:16/little, Prots:32/little>>,

			LI = byte_size(Head) + byte_size(RdpPart),
			{ok, <<LI:8, Head/binary, RdpPart/binary>>};

		#x224_dt{roa = ROA, eot = EOT, tpdunr = TpduNr, data = Data} ->
			Head = <<?PDU_DT:4, 0:3, ROA:1, EOT:1, TpduNr:7>>,
			LI = byte_size(Head),
			{ok, <<LI:8, Head/binary, Data/binary>>};

		#x224_dr{dst = DstRef, src = SrcRef, reason = Error} ->
			Reason = case Error of
				not_specified -> 0;
				congestion -> 1;
				not_attached -> 2;
				address_unknown -> 3;
				_ -> 0
			end,
			Head = <<?PDU_DR:4, 0:4, DstRef:16/big, SrcRef:16/big, Reason:8>>,
			LI = byte_size(Head),
			{ok, <<LI:8, Head/binary>>};

		_ ->
			{error, bad_x224}
	end.

-spec decode(Data :: binary()) -> {ok, term()} | {error, term()}.
decode(Data) ->
	case Data of
		<<LI:8, ?PDU_CR:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, ExtFmts:1, ExFlow:1, Rest/binary>> ->
			{Cookie, RdpData} = case binary:match(Rest, <<16#0d0a:16/big>>) of
				{Pos, _} ->
					<<Token:Pos/binary-unit:8, 16#0d0a:16/big, Rem/binary>> = Rest,
					{Token, Rem};
				_ ->
					{none, Rest}
			end,
			case RdpData of
				<<?RDP_NEGREQ:8, Flags:8, _Length:16/little, Protocols:32/little>> ->
					<<_:28, CredSSPEarly:1, _:1, CredSSP:1, Ssl:1>> = <<Protocols:32/big>>,
					Prots = if CredSSPEarly == 1 -> [credssp_early]; true -> [] end ++ if CredSSP == 1 -> [credssp]; true -> [] end ++ if Ssl == 1 -> [ssl]; true -> [] end,
					{ok, #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie, rdp_protocols = Prots}};
				_ ->
					{ok, #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie}}
			end;

		<<LI:8, ?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, ExtFmts:1, ExFlow:1, Rest/binary>> ->
			case Rest of
				<<?RDP_NEGRSP:8, Flags:8, _Length:16/little, Selected:32/little>> ->
					<<_:5, _Reserved:1, DynVcGfx:1, ExtData:1>> = <<Flags:8>>,
					Flags2 = if DynVcGfx == 1 -> [dynvc_gfx]; true -> [] end ++ if ExtData == 1 -> [extdata]; true -> [] end,
					<<_:28, CredSSPEarly:1, _:1, CredSSP:1, Ssl:1>> = <<Selected:32/big>>,
					Prots = if CredSSPEarly == 1 -> [credssp_early]; true -> [] end ++ if CredSSP == 1 -> [credssp]; true -> [] end ++ if Ssl == 1 -> [ssl]; true -> [] end,
					{ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_flags = Flags2, rdp_selected = Prots}};

				<<?RDP_NEGFAIL:8,  _Flags:8, _Length:16/little, Code:32/little>> ->
					Error = case Code of
						16#01 -> ssl_required;
						16#02 -> ssl_not_allowed;
						16#03 -> cert_not_on_server;
						16#04 -> bad_flags;
						16#05 -> credssp_required;
						16#06 -> ssl_with_user_auth_required;
						_ -> unknown
					end,
					{ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status = error, rdp_error = Error}};

				_ ->
					{ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_selected = []}}
			end;

		<<LI:8, ?PDU_DT:4, 0:3, ROA:1, EOT:1, TpduNr:7, Rest/binary>> ->
			{ok, #x224_dt{roa = ROA, eot = EOT, tpdunr = TpduNr, data = Rest}};

		<<LI:8, ?PDU_DR:4, 0:4, DstRef:16/big, SrcRef:16/big, Reason:8, Rest/binary>> ->
			Error = case Reason of
				0 -> not_specified;
				1 -> congestion;
				2 -> not_attached;
				3 -> address_unknown;
				_ -> unknown
			end,
			{ok, #x224_dr{dst = DstRef, src = SrcRef, reason = Error}};

		_ ->
			{error, bad_x224}
	end.
