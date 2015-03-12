%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(cliprdr).

-include("cliprdr.hrl").

-export([pretty_print/1]).
-export([encode/1, decode/1]).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(cliprdr_caps);
?pp(cliprdr_format_list);
?pp(cliprdr_cap_general);
?pp(cliprdr_monitor_ready);
pretty_print(_, _) ->
    no.

-define(msg_flags, [{skip, 13}, ascii_names, fail, ok]).

encode(#cliprdr_monitor_ready{flags = Flags}) ->
    encode(16#0001, Flags, <<>>);

encode(#cliprdr_format_list{flags = Flags, formats = Formats}) ->
    Data = iolist_to_binary([encode_long_format(F) || F <- Formats]),
    encode(16#0002, Flags, Data);

encode(#cliprdr_caps{flags = Flags, caps = Caps}) ->
    NSets = length(Caps),
    CapSets = iolist_to_binary([encode_cap(C) || C <- Caps]),
    Data = <<NSets:16/little, 0:16, CapSets/binary>>,
    encode(16#0007, Flags, Data);

encode(_) -> error(bad_record).

encode(Type, FlagList, Data) ->
    <<MsgFlags:16/big>> = rdpp:encode_bit_flags(sets:from_list(FlagList), ?msg_flags),
    Len = byte_size(Data),
    <<Type:16/little, MsgFlags:16/little, Len:32/little, Data/binary>>.

decode(<<MsgType:16/little, MsgFlags:16/little, Len:32/little, Data:Len/binary, Pad/binary>>) ->
    PadLen = 8 * byte_size(Pad),
    case Pad of
        <<0:PadLen>> ->
            MsgFlagSet = rdpp:decode_bit_flags(<<MsgFlags:16/big>>, ?msg_flags),
            decode(MsgType, MsgFlagSet, Data);
        _ ->
            {error, bad_packet_padding}
    end;
decode(_) ->
    {error, bad_packet}.

decode(16#0001, MsgFlags, _Data) ->
    {ok, #cliprdr_monitor_ready{flags = sets:to_list(MsgFlags)}};

decode(16#0002, MsgFlags, Data) ->
    Formats = decode_long_format(Data),
    {ok, #cliprdr_format_list{flags = sets:to_list(MsgFlags), formats = Formats}};

decode(16#0007, MsgFlags, Data) ->
    <<NSets:16/little, _:16, SetsBin/binary>> = Data,
    Caps = decode_caps_set(SetsBin, NSets),
    {ok, #cliprdr_caps{flags = sets:to_list(MsgFlags), caps = Caps}};

decode(MsgType, _, _) ->
    {error, {unknown_type, MsgType}}.

decode_long_format(<<>>) -> [];
decode_long_format(<<0>>) -> [];
decode_long_format(<<Id:32/little, Rest/binary>>) ->
    [Name0, Rem0] = binary:split(Rest, <<0, 0>>),
    {Name, Rem} = case Rem0 of
        <<0, AfterZero/binary>> -> {<<Name0/binary, 0>>, AfterZero};
        _ -> {Name0, Rem0}
    end,
    Fmt = case {Id, Name} of
        {1, _} -> text;
        {2, _} -> bitmap;
        {3, _} -> metafile;
        {4, _} -> sylk;
        {5, _} -> dif;
        {6, _} -> tiff;
        {7, _} -> oemtext;
        {8, _} -> dib;
        {9, _} -> palette;
        {10, _} -> pendata;
        {11, _} -> riff;
        {12, _} -> wave;
        {13, _} -> unicode;
        {14, _} -> enh_metafile;
        {15, _} -> hdrop;
        {16, _} -> locale;
        {_, _} -> {Id, unicode:characters_to_list(Name, {utf16, little})}
    end,
    [Fmt | decode_long_format(Rem)].

encode_long_format(text) -> <<1:32/little, 0, 0>>;
encode_long_format(bitmap) -> <<2:32/little, 0, 0>>;
encode_long_format(metafile) -> <<3:32/little, 0, 0>>;
encode_long_format(sylk) -> <<4:32/little, 0, 0>>;
encode_long_format(dif) -> <<5:32/little, 0, 0>>;
encode_long_format(tiff) -> <<6:32/little, 0, 0>>;
encode_long_format(oemtext) -> <<7:32/little, 0, 0>>;
encode_long_format(dib) -> <<8:32/little, 0, 0>>;
encode_long_format(palette) -> <<9:32/little, 0, 0>>;
encode_long_format(pendata) -> <<10:32/little, 0, 0>>;
encode_long_format(riff) -> <<11:32/little, 0, 0>>;
encode_long_format(wave) -> <<12:32/little, 0, 0>>;
encode_long_format(unicode) -> <<13:32/little, 0, 0>>;
encode_long_format(enh_metafile) -> <<14:32/little, 0, 0>>;
encode_long_format(hdrop) -> <<15:32/little, 0, 0>>;
encode_long_format(locale) -> <<16:32/little, 0, 0>>;
encode_long_format({Id, Name}) ->
    NameBin = unicode:characters_to_binary(Name, {utf16, little}),
    <<Id:32/little, NameBin/binary, 0, 0>>.

-define(gencap_flags, [{skip, 28}, locking, no_file_paths, files, long_names]).
decode_caps_set(_, 0) -> [];
decode_caps_set(<<>>, N) when N > 0 -> error({expected_cap_set, N});
decode_caps_set(<<Type:16/little, Len:16/little, Rest/binary>>, N) ->
    DataLen = Len - 4,
    <<Data:DataLen/binary, Rem/binary>> = Rest,
    case Type of
        16#01 ->
            <<Version:32/little, Flags:32/little>> = Data,
            FlagSet = rdpp:decode_bit_flags(<<Flags:32/big>>, ?gencap_flags),
            [#cliprdr_cap_general{flags = sets:to_list(FlagSet), version = Version} |
                decode_caps_set(Rem, N - 1)];
        _ -> error({unknown_cap_type, Type})
    end.

encode_cap(#cliprdr_cap_general{flags = FlagList, version = Version}) ->
    <<Flags:32/big>> = rdpp:encode_bit_flags(sets:from_list(FlagList), ?gencap_flags),
    Data = <<Version:32/little, Flags:32/little>>,
    Len = byte_size(Data) + 4,
    <<16#01:16/little, Len:16/little, Data/binary>>.

