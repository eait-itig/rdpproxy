%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(fastpath).

-include("rdpp.hrl").
-include("fastpath.hrl").

-export([decode_input/1, decode_output/1]).
-export([encode_output/1]).
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
?pp(ts_inpevt_key);
?pp(ts_inpevt_mouse);
?pp(ts_inpevt_wheel);
?pp(ts_inpevt_sync);
?pp(ts_inpevt_unicode);
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
			[#ts_inpevt_key{flags = FlagAtoms, action = Action, code = ScanCode} | decode_inp_events(Rem)];
		?FP_INP_MOUSEX ->
			<<PointerFlags:16/little, X:16/little, Y:16/little, Rem/binary>> = Rest,
			<<Down:1, _:13, Button5:1, Button4:1>> = <<PointerFlags:16/big>>,
			Action = if Down == 1 -> down; true -> up end,
			Buttons = if Button4 == 1 -> [4]; true -> [] end ++
					  if Button5 == 1 -> [5]; true -> [] end,
			[#ts_inpevt_mouse{point = {X,Y}, action = Action, buttons = Buttons} | decode_inp_events(Rem)];
		?FP_INP_MOUSE ->
			<<PointerFlags:16/little, X:16/little, Y:16/little, Rem/binary>> = Rest,
			<<Down:1, Button3:1, Button2:1, Button1:1, Move:1, _:1, Wheel:1, WheelNegative:1, Clicks:8>> = <<PointerFlags:16/big>>,
			if Wheel == 1 ->
				SignedClicks = if WheelNegative == 1 -> (0 - Clicks); true -> Clicks end,
				[#ts_inpevt_wheel{point = {X,Y}, clicks = SignedClicks} | decode_inp_events(Rem)];
			true ->
				Action = if Move == 1 -> move; Down == 1 -> down; true -> up end,
				Buttons = if Button3 == 1 -> [3]; true -> [] end ++
						  if Button2 == 1 -> [2]; true -> [] end ++
						  if Button1 == 1 -> [1]; true -> [] end,
				[#ts_inpevt_mouse{point = {X,Y}, action = Action, buttons = Buttons} | decode_inp_events(Rem)]
			end;
		?FP_INP_SYNC ->
			<<_:1, KanaLock:1, CapsLock:1, NumLock:1, ScrollLock:1>> = <<Flags:5>>,
			FlagAtoms = if KanaLock == 1 -> [kanalock]; true -> [] end ++
						if CapsLock == 1 -> [capslock]; true -> [] end ++
						if NumLock == 1 -> [numlock]; true -> [] end ++
						if ScrollLock == 1 -> [scrolllock]; true -> [] end,
			[#ts_inpevt_sync{flags = FlagAtoms} | decode_inp_events(Rest)];
		?FP_INP_UNICODE ->
			<<CodePoint:16/little, Rem/binary>> = Rest,
			<<_:4, Release:1>> = <<Flags:5>>,
			Action = if Release == 1 -> up; true -> down end,
			[#ts_inpevt_unicode{code = CodePoint, action = Action} | decode_inp_events(Rest)];
		Other ->
			[#fp_inp_unknown{type = Code, flags = Flags}]
	end.

decode_out_updates(_) -> [].

decode_input(Binary) ->
	decode(Binary, fun decode_inp_events/1).

decode_output(Binary) ->
	decode(Binary, fun decode_out_updates/1).

encode_update(#ts_update_orders{orders = Orders}) ->
	Count = length(Orders),
	OrdersBin = lists:foldl(fun(Order, Bin) ->
		B = rdpp:encode_ts_order(Order),
		<<Bin/binary, B/binary>>
	end, <<>>, Orders),
	Inner = <<Count:16/little, OrdersBin/binary>>,
	encode_update({16#00, single, Inner});

encode_update(Ub = #ts_update_bitmaps{bitmaps = Bitmaps}) ->
	Inner = rdpp:encode_ts_update_bitmaps(Ub),
	encode_update({16#01, single, Inner});

encode_update({Type, Fragment, Data}) ->
	Compression = 0,
	Fragmentation = case Fragment of
		single -> 0;
		last -> 1;
		first -> 2;
		next -> 3
	end,
	Size = byte_size(Data),
	<<Compression:2, Fragmentation:2, Type:4, Size:16/little, Data/binary>>.

encode_output(Pdu = #fp_pdu{flags = Flags, signature = Signature, contents = Contents}) when is_list(Contents) ->
	ContentsBin = lists:foldl(
		fun(Update, Bin) when is_binary(Update) ->
			<<Bin/binary, Update/binary>>;
		(Update, Bin) ->
			B = encode_update(Update),
			<<Bin/binary, B/binary>>
		end, <<>>, Contents),
	Encrypted = case lists:member(encrypted, Flags) of true -> 1; _ -> 0 end,
	SaltedMAC = case lists:member(salted_mac, Flags) of true -> 1; _ -> 0 end,
	LargeN = (length(Contents) >= 1 bsl 5),
	LargeSize = ((byte_size(ContentsBin) + 12) >= 1 bsl 8),
	HeaderLen = 1 + (if LargeSize -> 2; true -> 1 end) +
				(if LargeN -> 1; true -> 0 end) +
				(if Encrypted == 1 -> 8; true -> 0 end),
	TotalSize = HeaderLen + byte_size(ContentsBin),
	Header0 = if LargeN ->
		<<Encrypted:1, SaltedMAC:1, 0:4, ?ACT_FASTPATH:2>>;
	true ->
		<<Encrypted:1, SaltedMAC:1, (length(Contents)):4, ?ACT_FASTPATH:2>>
	end,
	Header1 = if LargeSize ->
		<<Header0/binary, 1:1, TotalSize:15/big>>;
	true ->
		<<Header0/binary, 0:1, TotalSize:7>>
	end,
	Header2 = if (Encrypted == 1) ->
		<<Header1/binary, Signature/binary>>;
	true ->
		Header1
	end,
	Header3 = if LargeN ->
		<<Header2/binary, TotalSize:8>>;
	true ->
		Header2
	end,
	<<Header3/binary, ContentsBin/binary>>.

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
