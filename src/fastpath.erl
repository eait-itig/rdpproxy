%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(fastpath).

-include("fastpath.hrl").

-export([decode_input/1, decode_output/1]).
-export([pretty_print/1]).

-define(pp(Rec),
pretty_print(Rec, N) ->
	N = record_info(size, Rec) - 1,
	record_info(fields, Rec)).

pretty_print(Record) ->
	io_lib_pretty:print(Record, fun pretty_print/2).
?pp(fp_pdu);
?pp(fp_inp_scancode);
?pp(fp_inp_mouse);
?pp(fp_inp_wheel);
?pp(fp_inp_sync);
?pp(fp_inp_unicode);
pretty_print(0, _) ->
	no.

-define(ACT_FASTPATH, 0).

-define(FP_INP_SCANCODE, 16#0).
-define(FP_INP_MOUSE, 16#1).
-define(FP_INP_MOUSEX, 16#2).
-define(FP_INP_SYNC, 16#3).
-define(FP_INP_UNICODE, 16#4).

decode_inp_events(<<>>) -> [];
decode_inp_events(<<Code:3, Flags:5, Rest/binary>>) ->
	case Code of
		?FP_INP_SCANCODE ->
			<<_:3, Extended:1, Release:1>> = <<Flags:5>>,
			FlagAtoms = if Extended == 1 -> [extended]; true -> [] end,
			Action = if Release == 1 -> up; true -> down end,
			<<ScanCode:8, Rem/binary>> = Rest,
			[#fp_inp_scancode{flags = FlagAtoms, action = Action, code = ScanCode} | decode_inp_events(Rem)];
		?FP_INP_MOUSEX ->
			<<PointerFlags:16/little, X:16/little, Y:16/little, Rem/binary>> = Rest,
			<<Down:1, _:13, Button5:1, Button4:1>> = <<PointerFlags:16/big>>,
			Action = if Down == 1 -> down; true -> up end,
			Buttons = if Button4 == 1 -> [4]; true -> [] end ++
					  if Button5 == 1 -> [5]; true -> [] end,
			[#fp_inp_mouse{point = {X,Y}, action = Action, buttons = Buttons} | decode_inp_events(Rem)];
		?FP_INP_MOUSE ->
			<<PointerFlags:16/little, X:16/little, Y:16/little, Rem/binary>> = Rest,
			<<Down:1, Button3:1, Button2:1, Button1:1, Move:1, _:1, Wheel:1, WheelNegative:1, Clicks:8>> = <<PointerFlags:16/big>>,
			if Wheel == 1 ->
				SignedClicks = if WheelNegative == 1 -> (0 - Clicks); true -> Clicks end,
				[#fp_inp_wheel{point = {X,Y}, clicks = SignedClicks} | decode_inp_events(Rem)];
			true ->
				Action = if Move == 1 -> move; Down == 1 -> down; true -> up end,
				Buttons = if Button3 == 1 -> [3]; true -> [] end ++
						  if Button2 == 1 -> [2]; true -> [] end ++
						  if Button1 == 1 -> [1]; true -> [] end,
				[#fp_inp_mouse{point = {X,Y}, action = Action, buttons = Buttons} | decode_inp_events(Rem)]
			end;
		?FP_INP_SYNC ->
			<<_:1, KanaLock:1, CapsLock:1, NumLock:1, ScrollLock:1>> = <<Flags:5>>,
			FlagAtoms = if KanaLock == 1 -> [kanalock]; true -> [] end ++
						if CapsLock == 1 -> [capslock]; true -> [] end ++
						if NumLock == 1 -> [numlock]; true -> [] end ++
						if ScrollLock == 1 -> [scrolllock]; true -> [] end,
			[#fp_inp_sync{flags = FlagAtoms} | decode_inp_events(Rest)];
		?FP_INP_UNICODE ->
			<<CodePoint:16/little, Rem/binary>> = Rest,
			<<_:4, Release:1>> = <<Flags:5>>,
			Action = if Release == 1 -> up; true -> down end,
			[#fp_inp_unicode{code = CodePoint, action = Action} | decode_inp_events(Rest)]
	end.

decode_out_updates(<<>>) -> [].

decode_input(Binary) ->
	decode(Binary, fun decode_inp_events/1).

decode_output(Binary) ->
	decode(Binary, fun decode_out_updates/1).

decode(Binary, Decoder) ->
	case Binary of
		<<1:1, SaltedMAC:1, 0:4, ?ACT_FASTPATH:2, 0:1, PduLength:7, Signature:8/binary, NumEvts:8, Rest/binary>> ->
			Len = PduLength - (1 + 1 + 8 + 1),
			<<Data:Len/binary, Rem/binary>> = Rest,
			Flags = [encrypted] ++
					if SaltedMAC == 1 -> [salted_mac]; true -> [] end,
			{ok, #fp_pdu{flags = Flags, signature = Signature, contents = Data}, Rem};
		<<1:1, SaltedMAC:1, NumEvts:4, ?ACT_FASTPATH:2, 0:1, PduLength:7, Signature:8/binary, Rest/binary>> ->
			Len = PduLength - (1 + 1 + 8),
			<<Data:Len/binary, Rem/binary>> = Rest,
			Flags = [encrypted] ++
					if SaltedMAC == 1 -> [salted_mac]; true -> [] end,
			{ok, #fp_pdu{flags = Flags, signature = Signature, contents = Data}, Rem};
		<<1:1, SaltedMAC:1, 0:4, ?ACT_FASTPATH:2, 1:1, PduLength:15/big, Signature:8/binary, NumEvts:8, Rest/binary>> ->
			Len = PduLength - (1 + 2 + 8 + 1),
			<<Data:Len/binary, Rem/binary>> = Rest,
			Flags = [encrypted] ++
					if SaltedMAC == 1 -> [salted_mac]; true -> [] end,
			{ok, #fp_pdu{flags = Flags, signature = Signature, contents = Data}, Rem};
		<<1:1, SaltedMAC:1, NumEvts:4, ?ACT_FASTPATH:2, 1:1, PduLength:15/big, Signature:8/binary, Rest/binary>> ->
			Len = PduLength - (1 + 2 + 8),
			<<Data:Len/binary, Rem/binary>> = Rest,
			Flags = [encrypted] ++
					if SaltedMAC == 1 -> [salted_mac]; true -> [] end,
			{ok, #fp_pdu{flags = Flags, signature = Signature, contents = Data}, Rem};
		<<0:1, 0:1, 0:4, ?ACT_FASTPATH:2, 0:1, PduLength:7, NumEvts:8, Rest/binary>> ->
			Len = PduLength - (1 + 1 + 1),
			<<Data:Len/binary, Rem/binary>> = Rest,
			{ok, #fp_pdu{flags = [], contents = Decoder(Data)}, Rem};
		<<0:1, 0:1, NumEvts:4, ?ACT_FASTPATH:2, 0:1, PduLength:7, Rest/binary>> ->
			Len = PduLength - (1 + 1),
			<<Data:Len/binary, Rem/binary>> = Rest,
			{ok, #fp_pdu{flags = [], contents = Decoder(Data)}, Rem};
		<<0:1, 0:1, 0:4, ?ACT_FASTPATH:2, 1:1, PduLength:15/big, NumEvts:8, Rest/binary>> ->
			Len = PduLength - (1 + 2 + 1),
			<<Data:Len/binary, Rem/binary>> = Rest,
			{ok, #fp_pdu{flags = [], contents = Decoder(Data)}, Rem};
		<<0:1, 0:1, NumEvts:4, ?ACT_FASTPATH:2, 1:1, PduLength:15/big, Rest/binary>> ->
			Len = PduLength - (1 + 2),
			<<Data:Len/binary, Rem/binary>> = Rest,
			{ok, #fp_pdu{flags = [], contents = Decoder(Data)}, Rem};
		_ -> {error, bad_packet}
	end.
