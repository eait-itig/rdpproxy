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
?pp(fp_inp_unknown);
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
			[#fp_inp_unicode{code = CodePoint, action = Action} | decode_inp_events(Rest)];
		Other ->
			[#fp_inp_unknown{type = Code, flags = Flags}]
	end.

decode_out_updates(_) -> [].

decode_input(Binary) ->
	decode(Binary, fun decode_inp_events/1).

decode_output(Binary) ->
	decode(Binary, fun decode_out_updates/1).

decode(Binary, Decoder) ->
	maybe([
		fun(Pdu = #fp_pdu{flags = Fl}, Bin) ->
			case Bin of
				<<Encrypted:1, SaltedMAC:1, NumEvts:4, ?ACT_FASTPATH:2, Rest/binary>> ->
					FlagAtoms = if Encrypted == 1 -> [encrypted]; true -> [] end ++
								if SaltedMAC == 1 -> [salted_mac]; true -> [] end,
					{continue, [Pdu#fp_pdu{flags = FlagAtoms}, Rest, (Encrypted == 1), NumEvts]};
				_ ->
					{return, {error, {bad_packet, header}}}
			end
		end,
		fun(Pdu, Bin, Encrypted, NumEvts) ->
			case Bin of
				<<0:1, PduLength:7, Rest/binary>> ->
					{continue, [Pdu, Rest, Encrypted, NumEvts, PduLength - 2]};
				<<1:1, PduLength:15/big, Rest/binary>> ->
					{continue, [Pdu, Rest, Encrypted, NumEvts, PduLength - 3]};
				_ ->
					{return, {error, {bad_packet, pdu_length}}}
			end
		end,
		fun(Pdu, Bin, Encrypted, NumEvts, PduLength) ->
			if Encrypted ->
				case Bin of
					<<Signature:8/binary, Rest/binary>> ->
						Pdu2 = Pdu#fp_pdu{signature = Signature},
						{continue, [Pdu2, Rest, Encrypted, NumEvts, PduLength - 8]};
					_ ->
						{return, {error, {bad_packet, num_evts}}}
				end;
			true ->
				{continue, [Pdu, Bin, Encrypted, NumEvts, PduLength]}
			end
		end,
		fun(Pdu, Bin, Encrypted, NumEvts, PduLength) ->
			case NumEvts of
				0 ->
					case Bin of
						<<RealNumEvts:8, Rest/binary>> ->
							{continue, [Pdu, Rest, Encrypted, RealNumEvts, PduLength - 1]};
						_ ->
							{return, {error, {bad_packet, num_evts}}}
					end;
				_ ->
					{continue, [Pdu, Bin, Encrypted, NumEvts, PduLength]}
			end
		end,
		fun(Pdu, Bin, Encrypted, NumEvts, PduLength) ->
			case Bin of
				<<Data:PduLength/binary, Rem/binary>> ->
					if not Encrypted ->
						Pdu2 = Pdu#fp_pdu{contents = Decoder(Data)},
						{return, {ok, Pdu2, Rem}};
					true ->
						Pdu2 = Pdu#fp_pdu{contents = Data},
						{return, {ok, Pdu2, Rem}}
					end;
				_ ->
					{return, {error, {bad_packet, length}}}
			end
		end
	], [#fp_pdu{}, Binary]).

maybe([], Args) -> error(no_return);
maybe([Fun | Rest], Args) ->
	case apply(Fun, Args) of
		{continue, NewArgs} ->
			maybe(Rest, NewArgs);
		{return, Value} ->
			Value
	end.
