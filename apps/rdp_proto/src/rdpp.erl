%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(rdpp).

-include("kbd.hrl").
-include("x224.hrl").
-include("rdpp.hrl").
-include("rdpp_bitfields.hrl").

-export([decode_client/1, decode_server/1, decode_connseq/1]).
-export([encode_protocol_flags/1, decode_protocol_flags/1]).
-export([decode_basic/1, decode_sharecontrol/1]).
-export([encode_basic/1, encode_sharecontrol/1]).
-export([encode_ts_order/1, encode_ts_update_bitmaps/1]).
-export([decode_ts_confirm/2]).
-export([encode_vchan/1, decode_vchan/1]).
-export([pretty_print/1]).

-export([decode_bit_flags/2, encode_bit_flags/2]).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(ts_security);
?pp(ts_info);
?pp(ts_demand);
?pp(ts_confirm);
?pp(ts_redir);
?pp(ts_deactivate);
?pp(ts_sharedata);
?pp(ts_license_vc);
?pp(ts_sync);
?pp(ts_control);
?pp(ts_fontlist);
?pp(ts_fontmap);
?pp(ts_input);
?pp(ts_heartbeat);

?pp(ts_update_orders);
?pp(ts_order_opaquerect);
?pp(ts_order_srcblt);
?pp(ts_order_line);

?pp(ts_bitmap);
?pp(ts_bitmap_comp_info);
?pp(ts_update_bitmaps);

?pp(ts_inpevt_sync);
?pp(ts_inpevt_key);
?pp(ts_inpevt_unicode);
?pp(ts_inpevt_mouse);
?pp(ts_inpevt_wheel);

?pp(ts_cap_general);
?pp(ts_cap_bitmap);
?pp(ts_cap_share);
?pp(ts_cap_order);
?pp(ts_cap_input);
?pp(ts_cap_font);
?pp(ts_cap_pointer);
?pp(ts_cap_vchannel);
?pp(ts_cap_control);
?pp(ts_cap_activation);
?pp(ts_cap_multifrag);
?pp(ts_cap_gdip);
?pp(ts_cap_bitmapcache);
?pp(ts_cap_bitmapcache_cell);
?pp(ts_cap_brush);
?pp(ts_cap_large_pointer);
?pp(ts_cap_bitmap_codecs);
?pp(ts_cap_bitmap_codec);
?pp(ts_cap_colortable);
?pp(ts_vchan);
pretty_print(_, _) ->
    no.

decode_client(Bin) ->
    decode(Bin, decode_output).

decode_server(Bin) ->
    decode(Bin, decode_input).

decode(Bin, Dirn) ->
    maybe([
        fun decoder_fastpath/2,
        fun decoder_tpkt/1,
        fun decoder_x224/2,
        fun decoder_mcs_generic/3
    ], [Bin, Dirn]).

decode_connseq(Bin) ->
    maybe([
        fun decoder_tpkt/1,
        fun decoder_x224/2,
        fun decoder_mcs_ci/3,
        fun decoder_mcs_cr/3,
        fun decoder_mcs_generic/3
    ], [Bin]).

decoder_fastpath(Bin, Dirn) ->
    case fastpath:Dirn(Bin) of
        {ok, Pdu, Rem} ->
            {return, {ok, {fp_pdu, Pdu}, Rem}};
        {error, _} ->
            {continue, [Bin]}
    end.

decoder_tpkt(Bin) ->
    case tpkt:decode(Bin) of
        {ok, Body, Rem} ->
            {continue, [Body, Rem]};
        {error, Reason} ->
            {return, {error, {tpkt, Reason}}}
    end.

decoder_x224(Body, Rem) ->
    case x224:decode(Body) of
        {ok, #x224_dt{eot = 1, tpdunr = 0, data = McsData} = Pdu} ->
            {continue, [Pdu, McsData, Rem]};
        {ok, Pdu} ->
            {return, {ok, {x224_pdu, Pdu}, Rem}};
        {error, Reason} ->
            {return, {error, {x224, Reason}}}
    end.

decoder_mcs_generic(Pdu, McsData, Rem) ->
    case mcsgcc:decode(McsData) of
        {ok, McsPkt} ->
            {return, {ok, {mcs_pdu, McsPkt}, Rem}};
        Err ->
            {return, {ok, {x224_pdu, Pdu}, Rem}}
    end.

decoder_mcs_ci(Pdu, McsData, Rem) ->
    case mcsgcc:decode_ci(McsData) of
        {ok, McsPkt} ->
            {return, {ok, {mcs_pdu, McsPkt}, Rem}};
        Other ->
            {continue, [Pdu, McsData, Rem]}
    end.

decoder_mcs_cr(Pdu, McsData, Rem) ->
    case mcsgcc:decode_cr(McsData) of
        {ok, McsPkt} ->
            {return, {ok, {mcs_pdu, McsPkt}, Rem}};
        Err ->
            {continue, [Pdu, McsData, Rem]}
    end.

decode_bit_flags(<<>>, _) -> sets:new();
decode_bit_flags(Bits, [{skip,N} | RestAtoms]) ->
    <<_Flags:N, Rest/bitstring>> = Bits,
    decode_bit_flags(Rest, RestAtoms);
decode_bit_flags(<<_Flag:1, Rest/bitstring>>, [skip | RestAtoms]) ->
    decode_bit_flags(Rest, RestAtoms);
decode_bit_flags(Bits, [{FlagAtom, Width} | RestAtoms]) ->
    <<Flag:Width/little, Rest/bitstring>> = Bits,
    case Flag of
        0 -> decode_bit_flags(Rest, RestAtoms);
        1 -> sets:add_element(FlagAtom, decode_bit_flags(Rest, RestAtoms));
        N -> sets:add_element({FlagAtom, N}, decode_bit_flags(Rest, RestAtoms))
    end;
decode_bit_flags(<<Flag:1, Rest/bitstring>>, [FlagAtom | RestAtoms]) ->
    case Flag of
        1 -> sets:add_element(FlagAtom, decode_bit_flags(Rest, RestAtoms));
        0 -> decode_bit_flags(Rest, RestAtoms)
    end.

encode_bit_flags(_FlagSet, []) -> <<>>;
encode_bit_flags(FlagSet, [{skip, N} | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    <<0:N, RestBin/bitstring>>;
encode_bit_flags(FlagSet, [skip | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    <<0:1, RestBin/bitstring>>;
encode_bit_flags(FlagSet, [{FlagAtom, Width} | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    case sets:is_element(FlagAtom, FlagSet) of
        true -> <<1:Width/little, RestBin/bitstring>>;
        false -> <<0:Width/little, RestBin/bitstring>>
    end;
encode_bit_flags(FlagSet, [FlagAtom | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    case sets:is_element(FlagAtom, FlagSet) of
        true -> <<1:1, RestBin/bitstring>>;
        false -> <<0:1, RestBin/bitstring>>
    end.

-spec encode_protocol_flags([atom()]) -> integer().
encode_protocol_flags(Protocols) ->
    <<Prots:32/big>> = encode_bit_flags(sets:from_list(Protocols), ?cc_prot_flags),
    Prots.

-spec decode_protocol_flags(integer()) -> [atom()].
decode_protocol_flags(Protocols) ->
    FlagSet = decode_bit_flags(<<Protocols:32/big>>, ?cc_prot_flags),
    sets:to_list(FlagSet).

-spec decode_sec_flags(integer()) -> {Type :: atom(), Flags :: [atom()]}.
decode_sec_flags(Flags) ->
    FlagSet = decode_bit_flags(<<Flags:16/big>>, ?sec_flags),
    TypesSet = sets:from_list(?sec_types),
    TypeSet = sets:intersection(FlagSet, TypesSet),
    Type = case sets:to_list(TypeSet) of
        [T] -> T;
        [] -> unknown
    end,
    {Type, sets:to_list(sets:subtract(FlagSet, TypesSet))}.

-spec encode_sec_flags({Type :: atom(), Flags :: [atom()]}) -> integer().
encode_sec_flags({Type, Flags}) ->
    FlagSet = sets:from_list([Type | Flags]),
    <<Out:16/big>> = encode_bit_flags(FlagSet, ?sec_flags),
    Out.

encode_vchan(#ts_vchan{flags = FlagList, data = Data}) ->
    <<Flags:32/big>> = encode_bit_flags(sets:from_list(FlagList), ?vchan_flags),
    Len = byte_size(Data),
    <<Len:32/little, Flags:32/little, Data/binary>>.

decode_vchan(<<Len:32/little, Flags:32/little, Data:Len/binary, Pad/binary>>) ->
    FlagSet = decode_bit_flags(<<Flags:32/big>>, ?vchan_flags),
    PadLen = 8*byte_size(Pad),
    <<0:PadLen>> = Pad,
    {ok, #ts_vchan{flags = sets:to_list(FlagSet), data = Data}};

decode_vchan(_) ->
    {error, bad_packet}.

encode_sharecontrol(Pdu) ->
    {InnerType, Inner} = case Pdu of
        #ts_demand{} -> {16#1, encode_ts_demand(Pdu)};
        #ts_confirm{} -> {16#3, encode_ts_confirm(Pdu)};
        #ts_deactivate{} -> {16#6, encode_ts_deactivate(Pdu)};
        #ts_redir{} -> {16#a, encode_ts_redir(Pdu)};
        #ts_sharedata{} -> {16#7, encode_sharedata(Pdu)}
    end,
    Channel = element(2, Pdu),
    Length = byte_size(Inner) + 6,
    Version = 16#01,
    <<Type:16/big>> = <<Version:12/big, InnerType:4>>,
    {ok, <<Length:16/little, Type:16/little, Channel:16/little, Inner/binary>>}.

decode_sharecontrol(Bin) ->
    case Bin of
        <<N:32/little, Length:16/little, Rest/binary>> when N =:= 0; N =:= 48 ->
            if
                (byte_size(Rest) == Length - 2) ->
                    decode_sharecontrol(<<Length:16/little, Rest/binary>>);
                true ->
                    {error, bad_length}
            end;
        <<Length:16/little, Type:16/little, Chan:16/little, Rest/binary>> ->
            case <<Type:16/big>> of
                <<_:7, 0:1, 1:4, InnerType:4>> ->
                    RealLength = byte_size(Rest) + 6,
                    if RealLength == Length ->
                        case InnerType of
                            16#1 -> decode_ts_demand(Chan, Rest);
                            16#3 -> decode_ts_confirm(Chan, Rest);
                            16#6 -> decode_ts_deactivate(Chan, Rest);
                            16#7 -> decode_sharedata(Chan, Rest);
                            16#a -> decode_ts_redir(Chan, Rest);
                            Type ->
                                lager:warning("unhandled sharecontrol: ~p", [Type]),
                                {error, badpacket}
                        end;
                    true ->
                        {error, badlength}
                    end;
                _ ->
                    {error, bad_type}
            end;
        _ ->
            {error, badpacket}
    end.

zero_pad(Bin, Len) when is_list(Bin) ->
    zero_pad(list_to_binary(Bin), Len);
zero_pad(Bin, Len) ->
    Rem = Len - byte_size(Bin),
    <<Bin/binary, 0:Rem/unit:8>>.

zerobin_to_string(Bin) ->
    [First|_] = binary:split(Bin, <<0>>),
    binary_to_list(First).

decode_tscaps(0, _) -> [];
decode_tscaps(N, Bin) ->
    <<Type:16/little, Size:16/little, Rest/binary>> = Bin,
    Len = Size - 4,
    <<Data:Len/binary, Rem/binary>> = Rest,
    [decode_tscap(Type, Data) | decode_tscaps(N-1, Rem)].

decode_tscap(16#1, Bin) ->
    <<MajorNum:16/little, MinorNum:16/little, _:16, _:16, _:16, ExtraFlags:16/little, _:16, _:16, _:16, RefreshRect:8, SuppressOutput:8>> = Bin,

    Major = case MajorNum of 1 -> windows; 2 -> os2; 3 -> macintosh; 4 -> unix; _ -> other end,
    Minor = case MinorNum of 1 -> win31x; 2 -> win95; 3 -> winnt; 4 -> os2v21; 5 -> powerpc; 6 -> macintosh; 7 -> native_x11; 8 -> pseudo_x11; _ -> other end,

    FlagSet = decode_bit_flags(<<ExtraFlags:16/big, RefreshRect:1, SuppressOutput:1>>, ?ts_cap_general_flags),

    #ts_cap_general{os = [Major, Minor], flags = sets:to_list(FlagSet)};

decode_tscap(16#2, Bin) ->
    <<Bpp:16/little, _:16, _:16, _:16, Width:16/little, Height:16/little, _:16, Resize:16/little, Compression:16/little, _:8, DrawingFlags:8, Multirect:16/little, _:16>> = Bin,
    FlagSet = decode_bit_flags(<<DrawingFlags:8, Resize:1, Compression:1, Multirect:1>>, ?ts_cap_bitmap_flags),
    #ts_cap_bitmap{bpp = Bpp, flags = sets:to_list(FlagSet), width = Width, height = Height};

decode_tscap(16#3, Bin) ->
    <<_TermDesc:16/unit:8, _:32, _:16, _:16, _:16, _:16, _:16, BaseFlags:16/little, OrderSupport:32/binary, _/binary>> = Bin,
    FlagSet = decode_bit_flags(<<BaseFlags:16/big>>, ?ts_cap_order_flags),
    OrderSet = decode_bit_flags(OrderSupport, ?ts_cap_orders),
    #ts_cap_order{flags = sets:to_list(FlagSet), orders = sets:to_list(OrderSet)};

decode_tscap(16#5, Bin) ->
    <<Flags:16/little, RemoteDetach:16/little, Control:16/little, Detach:16/little>> = Bin,
    FlagAtoms = if (RemoteDetach =/= 0) -> [{remote_detach, RemoteDetach}]; true -> [] end,
    ControlAtom = case Control of
        2 -> never;
        _ -> Control
    end,
    DetachAtom = case Detach of
        2 -> never;
        _ -> Detach
    end,
    #ts_cap_control{flags = FlagAtoms, control = ControlAtom, detach = DetachAtom};

decode_tscap(16#7, Bin) ->
    <<HelpKey:16/little, _:16, HelpExKey:16/little, WmKey:16/little>> = Bin,
    #ts_cap_activation{helpkey = HelpKey, helpexkey = HelpExKey, wmkey = WmKey};

decode_tscap(16#8, Bin) ->
    <<Color:16/little, _:16, CacheSize:16/little>> = Bin,
    Flags = if Color == 1 -> [color]; true -> [] end,
    #ts_cap_pointer{flags = Flags, cache_size = CacheSize};

decode_tscap(16#9, Bin) ->
    <<Chan:16/little, _:16>> = Bin,
    #ts_cap_share{channel = Chan};

decode_tscap(16#d, Bin) ->
    <<InputFlags:16/little, _:16, Layout:32/little, Type:32/little, SubType:32/little, FunKeys:32/little, ImeBin:64/binary>> = Bin,
    FlagSet = decode_bit_flags(<<InputFlags:16/big>>, ?ts_cap_input_flags),
    #ts_cap_input{flags = sets:to_list(FlagSet), ime = ImeBin, kbd_layout = Layout, kbd_type = Type, kbd_sub_type = SubType, kbd_fun_keys = FunKeys};

decode_tscap(16#e, Bin) ->
    case Bin of
        <<>> -> #ts_cap_font{};
        <<Fontlist:16/little, _:16>> ->
            Flags = if Fontlist == 1 -> [fontlist]; true -> [] end,
            #ts_cap_font{flags = Flags}
    end;

decode_tscap(16#14, Bin) ->
    maybe([
        fun(V) ->
            case Bin of
                <<Flags:32/little>> ->
                    {continue, [V, Flags]};
                <<Flags:32/little, ChunkSize:32/little>> ->
                    V2 = V#ts_cap_vchannel{chunksize = ChunkSize},
                    {continue, [V2, Flags]}
            end
        end,
        fun(V, Flags) ->
            <<_:30, CompressCtoS:1, CompressStoC:1>> = <<Flags:32/big>>,
            FlagAtoms = if CompressCtoS == 1 -> [compress_cs]; true -> [] end ++
                        if CompressStoC == 1 -> [compress_sc]; true -> [] end,
            {return, V#ts_cap_vchannel{flags=FlagAtoms}}
        end
    ], [#ts_cap_vchannel{}]);

decode_tscap(16#16, Bin) ->
    <<Supported:32/little, GdipVersion:32/little, CacheSupported:32/little, CacheEntries:10/binary, CacheChunkSizes:8/binary, ImageCacheProps:6/binary>> = Bin,
    FlagAtoms = if Supported > 0 -> [supported]; true -> [] end ++
                if CacheSupported > 0 -> [cache]; true -> [] end,
    {<<>>, CacheEntryPlist} = lists:foldl(fun(Atom, {Bin, Acc}) ->
        <<Val:16/little, Rest/binary>> = Bin,
        {Rest, [{Atom, Val} | Acc]}
    end, {CacheEntries, []}, [graphics,brush,pen,image,image_attr]),
    {<<>>, CacheSizePlist} = lists:foldl(fun(Atom, {Bin, Acc}) ->
        <<Val:16/little, Rest/binary>> = Bin,
        {Rest, [{Atom, Val} | Acc]}
    end, {CacheChunkSizes, []}, [graphics,brush,pen,image_attr]),
    {<<>>, ImageCachePlist} = lists:foldl(fun(Atom, {Bin, Acc}) ->
        <<Val:16/little, Rest/binary>> = Bin,
        {Rest, [{Atom, Val} | Acc]}
    end, {ImageCacheProps, []}, [size, total, max]),
    #ts_cap_gdip{flags=FlagAtoms, version = GdipVersion, cache_entries=CacheEntryPlist, cache_sizes=CacheSizePlist, image_cache=ImageCachePlist};

decode_tscap(16#1a, Bin) ->
    <<MaxSize:32/little>> = Bin,
    #ts_cap_multifrag{maxsize = MaxSize};

decode_tscap(16#04, Bin) ->
    <<_Pad1:32, _Pad2:32, _Pad3:32, _Pad4:32, _Pad5:32, _Pad6:32, Caches/binary>> = Bin,
    <<Cache0Entries:16/little, Cache0CellSize:16/little,
      Cache1Entries:16/little, Cache1CellSize:16/little,
      Cache2Entries:16/little, Cache2CellSize:16/little>> = Caches,
    #ts_cap_bitmapcache{flags=[], cells=[
        #ts_cap_bitmapcache_cell{count = Cache0Entries, size = Cache0CellSize},
        #ts_cap_bitmapcache_cell{count = Cache1Entries, size = Cache1CellSize},
        #ts_cap_bitmapcache_cell{count = Cache2Entries, size = Cache2CellSize}
    ]};

decode_tscap(16#13, Bin) ->
    <<Flags:16/little, _Pad2, NumCellCaches, Rest/binary>> = Bin,
    <<_:14, WaitingList:1, PersistentKeys:1>> = <<Flags:16/big>>,
    FlagAtoms = [rev2] ++
                if WaitingList == 1 -> [waiting_list]; true -> [] end ++
                if PersistentKeys == 1 -> [persistent_keys]; true -> [] end,
    {_Rem, Cells} = lists:foldl(fun(_, {CellBin, Acc}) ->
        <<CellInfo:32/little, CellRest/binary>> = CellBin,
        <<Persistent:1, NumEntries:31/big>> = <<CellInfo:32/big>>,
        CellFlags = if Persistent == 1 -> [persistent]; true -> [] end,
        Cell = #ts_cap_bitmapcache_cell{count = NumEntries, flags = CellFlags},
        {CellRest, [Cell | Acc]}
    end, {Rest, []}, lists:seq(1, NumCellCaches)),
    #ts_cap_bitmapcache{flags = FlagAtoms, cells = lists:reverse(Cells)};

decode_tscap(16#0f, Bin) ->
    <<SupportLevel:32/little>> = Bin,
    Flags = case SupportLevel of
        0 -> [];
        1 -> [color_8x8];
        2 -> [color_8x8, color_full];
        N when N > 2 -> [color_8x8, color_full, other]
    end,
    #ts_cap_brush{flags = Flags};

decode_tscap(16#1b, Bin) ->
    <<Flags:16/little>> = Bin,
    <<_:15, Support96:1>> = <<Flags:16/big>>,
    FlagAtoms = if Support96 == 1 -> [support_96x96]; true -> [] end,
    #ts_cap_large_pointer{flags = FlagAtoms};

decode_tscap(16#1d, Bin) ->
    <<CodecCount, CodecsBin/binary>> = Bin,
    {<<>>, Codecs} = lists:foldl(fun(_, {CodecBin, Acc}) ->
        <<Guid:16/binary, Id, PropLen:16/little, PropBin:PropLen/binary, Rest/binary>> = CodecBin,
        {Name, Props} = case Guid of
            ?GUID_NSCODEC ->
                <<DynFidelity, Subsampling, ColorLossLevel>> = PropBin,
                {nscodec, [{dynamic_fidelity, DynFidelity == 1},
                           {subsampling, Subsampling == 1},
                           {color_loss_level, ColorLossLevel}]};
            ?GUID_JPEG ->
                <<Quality>> = PropBin,
                {jpeg, [{quality, Quality}]};
            ?GUID_REMOTEFX ->
                {remotefx, []};
            ?GUID_REMOTEFX_IMAGE ->
                {remotefx_image, PropBin};
            ?GUID_IGNORE ->
                {ignore, []};
            _ ->
                {unknown, PropBin}
        end,
        Codec = #ts_cap_bitmap_codec{codec = Name, guid = Guid, id = Id, properties = Props},
        {Rest, [Codec | Acc]}
    end, {CodecsBin, []}, lists:seq(1, CodecCount)),
    #ts_cap_bitmap_codecs{codecs = lists:reverse(Codecs)};

decode_tscap(16#0a, Bin) ->
    <<Size:16/little, _:16>> = Bin,
    #ts_cap_colortable{cache_size = Size};

decode_tscap(Type, Bin) ->
    {Type, Bin}.

encode_tscap(#ts_cap_general{os = [Major,Minor], flags=Flags}) ->
    MajorNum = case Major of windows -> 1; os2 -> 2; macintosh -> 3; unix -> 4; _ -> 0 end,
    MinorNum = case Minor of win31x -> 1; win95 -> 2; winnt -> 3; os2v21 -> 4; powerpc -> 5; macintosh -> 6; native_x11 -> 7; pseudo_x11 -> 8; _ -> 0 end,
    <<ExtraFlags:16/big, RefreshRect:1, SuppressOutput:1>> = encode_bit_flags(sets:from_list(Flags), ?ts_cap_general_flags),
    Inner = <<MajorNum:16/little, MinorNum:16/little, 16#200:16/little, 0:16, 0:16, ExtraFlags:16/little, 0:16, 0:16, 0:16, RefreshRect:8, SuppressOutput:8>>,
    encode_tscap({16#01, Inner});

encode_tscap(#ts_cap_vchannel{flags=FlagAtoms, chunksize=ChunkSize}) ->
    CompressCS = case lists:member(compress_cs, FlagAtoms) of true -> 1; _ -> 0 end,
    CompressSC = case lists:member(compress_sc, FlagAtoms) of true -> 1; _ -> 0 end,
    <<Flags:32/big>> = <<0:30, CompressCS:1, CompressSC:1>>,
    Inner = <<Flags:32/little, ChunkSize:32/little>>,
    encode_tscap({16#14, Inner});

encode_tscap(#ts_cap_bitmap{bpp = Bpp, flags = Flags, width = Width, height = Height}) ->
    <<DrawingFlags:8, Resize:1, Compression:1, Multirect:1>> = encode_bit_flags(sets:from_list(Flags), ?ts_cap_bitmap_flags),
    Inner = <<Bpp:16/little, 1:16/little, 1:16/little, 1:16/little, Width:16/little, Height:16/little, 0:16, Resize:16/little, Compression:16/little, 0:8, DrawingFlags:8, Multirect:16/little, 0:16>>,
    % this is different in the example versus spec
    encode_tscap({16#02, Inner});

encode_tscap(#ts_cap_order{flags = Flags, orders = Orders}) ->
    OrderSupport = encode_bit_flags(sets:from_list(Orders), ?ts_cap_orders),
    <<BaseFlags:16/big>> = encode_bit_flags(sets:from_list(Flags), ?ts_cap_order_flags),
    Inner = <<0:16/unit:8, 16#40420f00:32/big, 1:16/little, 20:16/little, 0:16, 1:16/little, 0:16, BaseFlags:16/little, OrderSupport/binary, 16#06a1:16/big, 0:16, 16#40420f00:32/big, 230400:32/little, 1:16/little, 0:16, 0:16, 0:16>>,
    encode_tscap({16#03, Inner});

encode_tscap(#ts_cap_share{channel = Chan}) ->
    Inner = <<Chan:16/little, 16#dce2:16/big>>,
    encode_tscap({16#09, Inner});

encode_tscap(#ts_cap_activation{helpkey=HelpKey, helpexkey=HelpExKey, wmkey=WmKey}) ->
    Inner = <<HelpKey:16/little, 0:16, HelpExKey:16/little, WmKey:16/little>>,
    encode_tscap({16#07, Inner});

encode_tscap(#ts_cap_control{control=ControlAtom, detach=DetachAtom}) ->
    Control = case ControlAtom of
        never -> 2
    end,
    Detach = case DetachAtom of
        never -> 2
    end,
    Inner = <<0:16, 0:16, Control:16/little, Detach:16/little>>,
    encode_tscap({16#05, Inner});

encode_tscap(#ts_cap_font{flags = Flags}) ->
    Fontlist = case lists:member(fontlist, Flags) of true -> 1; _ -> 0 end,
    Inner = <<Fontlist:16/little, 0:16>>,
    encode_tscap({16#0e, Inner});

encode_tscap(#ts_cap_pointer{flags = Flags, cache_size = CacheSize}) ->
    Color = case lists:member(color, Flags) of true -> 1; _ -> 0 end,
    Inner = <<Color:16/little, CacheSize:16/little, CacheSize:16/little>>,
    encode_tscap({16#08, Inner});

encode_tscap(#ts_cap_input{flags=Flags, kbd_layout=Layout, kbd_type=Type, kbd_sub_type=SubType, kbd_fun_keys=FunKeys, ime=Ime}) ->
    ImeBin = zero_pad(Ime, 64),
    <<InputFlags:16/big>> = encode_bit_flags(sets:from_list(Flags), ?ts_cap_input_flags),
    Inner = <<InputFlags:16/little, 0:16, Layout:32/little, Type:32/little, SubType:32/little, FunKeys:32/little, ImeBin/binary>>,
    encode_tscap({16#0d, Inner});

encode_tscap(#ts_cap_multifrag{maxsize = MaxSize}) ->
    encode_tscap({16#1a, <<MaxSize:32/little>>});

encode_tscap(#ts_cap_gdip{flags=FlagAtoms, version=GdipVersion, cache_entries=CacheEntryPlist, cache_sizes=CacheSizePlist, image_cache=ImageCachePlist}) ->
    CacheEntries = lists:foldl(fun({Atom, Default}, Bin) ->
        Val = proplists:get_value(Atom, CacheEntryPlist, Default),
        <<Bin/binary, Val:16/little>>
    end, <<>>, [{graphics, 10},{brush, 5},{pen, 5},{image, 10},{image_attr, 2}]),
    CacheChunkSizes = lists:foldl(fun({Atom, Default}, Bin) ->
        Val = proplists:get_value(Atom, CacheSizePlist, Default),
        <<Bin/binary, Val:16/little>>
    end, <<>>, [{graphics, 512},{brush, 2048},{pen, 1024},{image_attr, 64}]),
    ImageCacheProps = lists:foldl(fun({Atom, Default}, Bin) ->
        Val = proplists:get_value(Atom, ImageCachePlist, Default),
        <<Bin/binary, Val:16/little>>
    end, <<>>, [{chunk, 4096}, {total, 256}, {max, 128}]),
    Supported = case lists:member(supported, FlagAtoms) of true -> 1; _ -> 0 end,
    CacheSupported = case lists:member(cache, FlagAtoms) of true -> 1; _ -> 0 end,
    Inner = <<Supported:32/little, GdipVersion:32/little, CacheSupported:32/little, CacheEntries/binary, CacheChunkSizes/binary, ImageCacheProps/binary>>,
    encode_tscap({16#16, Inner});

encode_tscap(#ts_cap_large_pointer{flags = FlagAtoms}) ->
    Support96 = case lists:member(support_96x96, FlagAtoms) of true -> 1; _ -> 0 end,
    <<Flags:16/big>> = <<0:15, Support96:1>>,
    encode_tscap({16#1b, <<Flags:16/little>>});

encode_tscap(#ts_cap_bitmap_codecs{codecs = Codecs}) ->
    CodecCount = length(Codecs),
    CodecsBin = lists:foldl(
        fun(Codec = #ts_cap_bitmap_codec{codec = Name, id = Id, properties = Props}, Acc) ->
            {Guid, PropBin} = case Name of
                nscodec ->
                    DynFidelity = case proplists:get_value(dynamic_fidelity, Props) of true -> 1; _ -> 0 end,
                    Subsampling = case proplists:get_value(subsampling, Props) of true -> 1; _ -> 0 end,
                    ColorLossLevel = case proplists:get_value(color_loss_level, Props) of I when is_integer(I) -> I; _ -> 0 end,
                    {?GUID_NSCODEC, <<DynFidelity, Subsampling, ColorLossLevel>>};
                jpeg ->
                    Quality = case proplists:get_value(quality, Props) of I when is_integer(I) -> I; _ -> 75 end,
                    {?GUID_JPEG, <<Quality>>};
                remotefx -> {?GUID_REMOTEFX, <<0:32>>};
                remotefx_image when is_binary(Props) -> {?GUID_REMOTEFX_IMAGE, Props};
                ignore -> {?GUID_IGNORE, <<0:32>>};
                _ when is_binary(Props) -> {Codec#ts_cap_bitmap_codec.guid, Props}
            end,
            PropLen = byte_size(PropBin),
            <<Acc/binary, Guid/binary, Id, PropLen:16/little, PropBin/binary>>
        end, <<>>, Codecs),
    encode_tscap({16#1d, <<CodecCount, CodecsBin/binary>>});

encode_tscap(#ts_cap_colortable{cache_size = Size}) ->
    encode_tscap({16#0a, <<Size:16/little, 0:16>>});

encode_tscap({Type, Bin}) ->
    Size = byte_size(Bin) + 4,
    <<Type:16/little, Size:16/little, Bin/binary>>.

decode_ts_demand(Chan, Bin) ->
    case Bin of
        <<ShareId:32/little, SDLen:16/little, Len:16/little, Rest/binary>> ->
            case Rest of
                <<SD:SDLen/binary, N:16/little, _:16, CapsBin/binary>> ->
                    RealLen = byte_size(CapsBin) + 4,
                    if (Len == RealLen) or (Len + 4 == RealLen) ->
                        Caps = decode_tscaps(N, CapsBin),
                        {ok, #ts_demand{channel = Chan, shareid = ShareId, sourcedesc = SD, capabilities = Caps}};
                    true ->
                        {error, {badlength, Len, RealLen}}
                    end;
                _ ->
                    {error, badpacket}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_demand(#ts_demand{shareid = ShareId, sourcedesc = SourceDesc, capabilities = Caps}) ->
    N = length(Caps),
    CapsBin = lists:foldl(fun(Next, Bin) ->
        NextBin = encode_tscap(Next), <<Bin/binary, NextBin/binary>>
    end, <<>>, Caps),
    SDLen = byte_size(SourceDesc),
    Sz = byte_size(CapsBin) + 4,
    <<ShareId:32/little, SDLen:16/little, Sz:16/little, SourceDesc/binary, N:16/little, 0:16, CapsBin/binary, 0:32/little>>.

decode_ts_confirm(Chan, Bin) ->
    case Bin of
        <<ShareId:32/little, _:16, SDLen:16/little, Len:16/little, Rest/binary>> ->
            case Rest of
                <<SD:SDLen/binary, N:16/little, _:16, CapsBin/binary>> ->
                    RealLen = byte_size(CapsBin) + 4,
                    if (Len == RealLen) ->
                        Caps = decode_tscaps(N, CapsBin),
                        {ok, #ts_confirm{channel = Chan, shareid = ShareId, sourcedesc = SD, capabilities = Caps}};
                    true ->
                        {error, badlength}
                    end;
                _ ->
                    {error, badpacket}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_confirm(#ts_confirm{}) ->
    <<>>.

decode_ts_deactivate(Chan, Bin) ->
    {ok, #ts_deactivate{channel = Chan}}.

encode_ts_deactivate(#ts_deactivate{shareid = ShareId, sourcedesc = SourceDescIn}) ->
    SourceDesc = if is_binary(SourceDescIn) and (byte_size(SourceDescIn) > 0) -> SourceDescIn; true -> <<0>> end,
    Sz = byte_size(SourceDesc),
    <<ShareId:32/little, Sz:16/little, SourceDesc/binary>>.

decode_ts_redir(Chan, Bin) ->
    {ok, #ts_redir{channel = Chan}}.

encode_ts_redir(#ts_redir{sessionid = Session, username = Username, domain = Domain, password = Password, cookie = Cookie, flags = Flags, address = NetAddress, fqdn = Fqdn}) ->
    InfoOnly = case lists:member(info_only, Flags) of true -> 1; _ -> 0 end,
    Smartcard = case lists:member(smartcard, Flags) of true -> 1; _ -> 0 end,
    Logon = case lists:member(logon, Flags) of true -> 1; _ -> 0 end,

    HasCookie = if is_binary(Cookie) and (byte_size(Cookie) > 0) -> 1; true -> 0 end,
    HasUsername = if is_binary(Username) and (byte_size(Username) > 0) -> 1; true -> 0 end,
    HasDomain = if is_binary(Domain) and (byte_size(Domain) > 0) -> 1; true -> 0 end,
    HasPassword = if is_binary(Password) and (byte_size(Password) > 0) -> 1; true -> 0 end,
    HasNetAddress = if is_binary(NetAddress) and (byte_size(NetAddress) > 0) -> 1; true -> 0 end,
    HasFqdn = if is_binary(Fqdn) and (byte_size(Fqdn) > 0) -> 1; true -> 0 end,

    %if (HasNetAddress == 1) andalso (HasCookie == 1) ->
    %   error(cookie_and_netaddr);
    %true -> ok end,

    UseCookieForTsv = 0,
    HasTsvUrl = 0,
    HasMultiNetAddr = 0,
    HasNetBios = 0,

    <<RedirFlags:32/big>> = <<0:19, UseCookieForTsv:1, HasTsvUrl:1, HasMultiNetAddr:1, HasNetBios:1, HasFqdn:1, InfoOnly:1, Smartcard:1, Logon:1, HasPassword:1, HasDomain:1, HasUsername:1, HasCookie:1, HasNetAddress:1>>,

    maybe([
        fun() ->
            {continue, [<<Session:32/little, RedirFlags:32/little>>]}
        end,
        fun(Base) ->
            {continue, [if HasNetAddress == 1 ->
                S = byte_size(NetAddress),
                <<Base/binary, S:32/little, NetAddress/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasCookie == 1 ->
                S = byte_size(Cookie),
                <<Base/binary, S:32/little, Cookie/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasUsername == 1 ->
                S = byte_size(Username),
                <<Base/binary, S:32/little, Username/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasDomain == 1 ->
                S = byte_size(Domain),
                <<Base/binary, S:32/little, Domain/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasPassword == 1 ->
                S = byte_size(Password),
                <<Base/binary, S:32/little, Password/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasFqdn == 1 ->
                S = byte_size(Fqdn),
                <<Base/binary, S:32/little, Fqdn/binary>>;
            true -> Base end]}
        end,
        fun(Payload) ->
            Len = byte_size(Payload) + 4,
            {return, <<0:16, 16#0400:16/little, Len:16/little, Payload/binary, 0:9/unit:8>>}
        end
    ], []).

decode_sharedata(Chan, Bin) ->
    case Bin of
        <<ShareId:32/little, _:8, Priority:8, Length:16/little, PduType:8, Flags:4, CompType:4, CompressedLength:16/little, Rest/binary>> ->
            <<Flushed:1, AtFront:1, Compressed:1, _:1>> = <<Flags:4>>,
            FlagAtoms = if Flushed == 1 -> [flushed]; true -> [] end ++
                        if AtFront == 1 -> [at_front]; true -> [] end ++
                        if Compressed == 1 -> [compressed]; true -> [] end,
            Prio = case Priority of 1 -> low; 2 -> medium; 4 -> high; _ -> unknown end,
            CompTypeAtom = case CompType of 0 -> '8k'; 1 -> '64k'; 2 -> 'rdp6'; 3 -> 'rdp61'; _ -> 'unknown' end,
            RealSize = byte_size(Rest),
            if (Compressed == 1) and (CompressedLength == RealSize) ->
                {ok, #ts_sharedata{channel = Chan, shareid = ShareId, priority = Prio, flags = FlagAtoms, comptype = CompTypeAtom, data = {PduType, Rest}}};
            (Compressed == 0) -> %and (Length == RealSize) ->
                Inner = case PduType of
                    %16#02 -> decode_update(Rest);
                    31 -> decode_ts_sync(Rest);
                    20 -> decode_ts_control(Rest);
                    39 -> decode_ts_fontlist(Rest);
                    40 -> decode_ts_fontmap(Rest);
                    28 -> decode_ts_input(Rest);
                    36 -> decode_ts_shutdown(Rest);
                    _ -> {PduType, Rest}
                end,
                {ok, #ts_sharedata{channel = Chan, shareid = ShareId, priority = Prio, flags = FlagAtoms, data = Inner}};
            true ->
                {error, {badlength, Length, CompressedLength, RealSize}}
            end;
        _ ->
            {error, badpacket}
    end.

encode_sharedata(#ts_sharedata{shareid = ShareId, data = Pdu, priority = Prio, comptype = CompTypeAtom, flags = FlagAtoms}) ->
    {PduType, Inner} = case Pdu of
        %#ts_update{} -> {16#02, encode_ts_update(Pdu)};
        #ts_sync{} -> {31, encode_ts_sync(Pdu)};
        #ts_control{} -> {20, encode_ts_control(Pdu)};
        #ts_fontlist{} -> {39, encode_ts_fontlist(Pdu)};
        #ts_fontmap{} -> {40, encode_ts_fontmap(Pdu)};
        #ts_update_orders{} -> {2, encode_ts_update(Pdu)};
        #ts_update_bitmaps{} -> {2, encode_ts_update(Pdu)};
        {N, Data} -> {N, Data}
    end,
    CompType = case CompTypeAtom of '8k' -> 0; '64k' -> 1; 'rdp6' -> 2; 'rdp61' -> 3; _ -> 4 end,
    Priority = case Prio of low -> 1; medium -> 2; high -> 4; _ -> 0 end,

    Flushed = case lists:member(flushed, FlagAtoms) of true -> 1; _ -> 0 end,
    AtFront = case lists:member(at_front, FlagAtoms) of true -> 1; _ -> 0 end,
    Compressed = case lists:member(compressed, FlagAtoms) of true -> 1; _ -> 0 end,
    <<Flags:4>> = <<Flushed:1, AtFront:1, Compressed:1, 0:1>>,

    Size = byte_size(Inner) + 6 + 12,
    <<ShareId:32/little, 0:8, Priority:8, Size:16/little, PduType:8, Flags:4, CompType:4, Size:16/little, Inner/binary>>.

decode_ts_sync(Bin) ->
    <<1:16/little, User:16/little>> = Bin,
    #ts_sync{user = User}.

encode_ts_sync(#ts_sync{user = User}) ->
    <<1:16/little, User:16/little>>.

decode_ts_control(Bin) ->
    <<Action:16/little, GrantId:16/little, ControlId:32/little>> = Bin,
    ActionAtom = case Action of 1 -> request; 2 -> granted; 3 -> detach; 4 -> cooperate end,
    #ts_control{action = ActionAtom, grantid = GrantId, controlid = ControlId}.

encode_ts_control(#ts_control{action = ActionAtom, grantid = GrantId, controlid = ControlId}) ->
    Action = case ActionAtom of request -> 1; granted -> 2; detach -> 3; cooperate -> 4 end,
    <<Action:16/little, GrantId:16/little, ControlId:32/little>>.

decode_ts_fontlist(Bin) ->
    #ts_fontlist{}.

encode_ts_fontlist(#ts_fontlist{}) ->
    <<0:16, 0:16, 3:16/little, 50:16/little>>.

decode_ts_fontmap(Bin) ->
    #ts_fontmap{}.

encode_ts_fontmap(#ts_fontmap{}) ->
    <<0:16, 0:16, 3:16/little, 4:16/little>>.

encode_ts_update(Rec) ->
    {Type, Inner} = case Rec of
        #ts_update_orders{} -> {0, encode_ts_update_orders(Rec)};
        #ts_update_bitmaps{} -> {1, encode_ts_update_bitmaps(Rec)}
    end,
    <<Type:16/little, Inner/binary>>.

ceil(X) ->
    T = erlang:trunc(X),
    case (X - T) of
        Neg when Neg < 0 -> T;
        Pos when Pos > 0 -> T + 1;
        _ -> T
    end.

encode_ts_order_control_flags(Flags) ->
    Standard = 1,
    TypeChange = 1,
    Bounds = 0,
    Secondary = case lists:member(secondary, Flags) of true -> 1; _ -> 0 end,
    Delta = case lists:member(delta, Flags) of true -> 1; _ -> 0 end,
    ZeroBoundsDelta = 0,
    FieldZeros = 0,

    <<ControlFlags:8>> = <<FieldZeros:2, ZeroBoundsDelta:1, Delta:1, TypeChange:1, Bounds:1, Secondary:1, Standard:1>>,
    ControlFlags.

encode_secondary_ts_order(Type, Flags, ExtraFlags, Inner) ->
    ControlFlags = encode_ts_order_control_flags([secondary | Flags]),
    % the -13 here is for historical reasons, see the spec
    OrderLen = byte_size(Inner) + 6 - 13,
    <<ControlFlags:8, OrderLen:16/little, ExtraFlags:16/little, Type:8, Inner/binary>>.

encode_primary_ts_order(Type, Fields, Flags, Inner) ->
    ControlFlags = encode_ts_order_control_flags(Flags),
    % primary drawing orders use the crazy bit string to identify
    % which params are being given and which are not
    FieldBits = ceil((length(Fields) + 1.0) / 8.0) * 8,
    Shortfall = FieldBits - length(Fields),
    FieldShort = lists:foldl(fun(Next, Bin) ->
        <<Next:1, Bin/bitstring>>
    end, <<>>, Fields),
    <<FieldN:FieldBits/big>> = <<0:Shortfall, FieldShort/bitstring>>,

    <<ControlFlags:8, Type:8, FieldN:FieldBits/little, Inner/binary>>.

encode_ts_order(#ts_order_opaquerect{flags = Flags, dest={X,Y}, size={W,H}, color={R,G,B}}) ->
    Inner = <<X:16/little-signed, Y:16/little-signed, W:16/little-signed, H:16/little-signed, R:8, G:8, B:8>>,
    encode_primary_ts_order(16#0a, [1,1,1,1,1,1,1], Flags, Inner);

encode_ts_order(#ts_order_srcblt{flags = Flags, dest = {X1,Y1}, src = {X2, Y2}, size = {W,H}, rop = Rop}) ->
    Inner = <<X1:16/little-signed, Y1:16/little-signed, W:16/little-signed, H:16/little-signed, Rop:8, X2:16/little, Y2:16/little>>,
    encode_primary_ts_order(16#02, [1,1,1,1,1,1,1], Flags, Inner);

encode_ts_order(#ts_order_line{start = {X1,Y1}, finish = {X2,Y2}, flags = Flags, rop = Rop, color = {R,G,B}}) ->
    Inner = <<X1:16/little-signed, Y1:16/little-signed, X2:16/little-signed, Y2:16/little-signed, Rop:8, R:8, G:8, B:8>>,
    encode_primary_ts_order(16#09, [0,1,1,1,1,0,1,0,0,1], Flags, Inner).

encode_ts_update_orders(#ts_update_orders{orders = Orders}) ->
    OrdersBin = lists:foldl(fun(Next, Bin) ->
        Encode = encode_ts_order(Next),
        <<Bin/binary, Encode/binary>>
    end, <<>>, Orders),
    N = length(Orders),
    <<0:16, N:16/little, 0:16, OrdersBin/binary>>.

encode_ts_bitmap(#ts_bitmap{dest={X,Y}, size={W,H}, bpp=Bpp, comp_info=CompInfo, data=Data}) ->
    #ts_bitmap_comp_info{flags=CompFlags, scan_width=ScanWidth, full_size=FullSize} = CompInfo,
    Compressed = lists:member(compressed, CompFlags),
    ComprFlag = case Compressed of true -> 1; _ -> 0 end,
    NoComprFlag = case ScanWidth of undefined -> 1; _ -> 0 end,
    <<Flags:16/big>> = <<0:5, NoComprFlag:1, 0:9, ComprFlag:1>>,
    X2 = X + W,
    Y2 = Y + H,
    Body = if
        NoComprFlag == 0 ->
            CompSize = byte_size(Data),
            CompHdr = <<0:16, CompSize:16/little, ScanWidth:16/little, FullSize:16/little>>,
            <<CompHdr/binary, Data/binary>>;
        NoComprFlag == 1 ->
            Data
    end,
    BodyLength = byte_size(Body),
    <<X:16/little, Y:16/little, X2:16/little, Y2:16/little, W:16/little, H:16/little, Bpp:16/little, Flags:16/little, BodyLength:16/little, Body/binary>>.

encode_ts_update_bitmaps(#ts_update_bitmaps{bitmaps = Bitmaps}) ->
    N = length(Bitmaps),
    BitmapsBin = lists:foldl(fun(Next, Bin) ->
        Encode = encode_ts_bitmap(Next),
        <<Bin/binary, Encode/binary>>
    end, <<>>, Bitmaps),
    <<N:16/little, BitmapsBin/binary>>.

decode_ts_inpevt(16#0000, Bin) ->
    <<_:16, Flags:16/little, Rest/binary>> = Bin,
    FlagSet = decode_bit_flags(<<Flags:16/big>>, ?ts_inpevt_sync_flags),
    {#ts_inpevt_sync{flags=sets:to_list(FlagSet)}, Rest};

decode_ts_inpevt(16#0004, Bin) ->
    <<Flags:16/little, KeyCode:16/little, _:16, Rest/binary>> = Bin,
    <<Release:1, AlreadyDown:1, _:5, Extended:1, _:8>> = <<Flags:16/big>>,
    Action = if Release == 1 -> up; true -> down end,
    FlagAtoms = if AlreadyDown == 1 -> [already_down]; true -> [] end ++
                if Extended == 1 -> [extended]; true -> [] end,
    {#ts_inpevt_key{code = kbd:process_scancode(KeyCode), action = Action, flags = FlagAtoms}, Rest};

decode_ts_inpevt(16#0005, Bin) ->
    <<Flags:16/little, KeyCode:16/little, _:16, Rest/binary>> = Bin,
    <<Release:1, _:15>> = <<Flags:16/big>>,
    Action = if Release == 1 -> up; true -> down end,
    {#ts_inpevt_unicode{code = KeyCode, action = Action}, Rest};

decode_ts_inpevt(16#8001, Bin) ->
    <<Flags:16/little, X:16/little, Y:16/little, Rest/binary>> = Bin,
    <<Down:1, Button3:1, Button2:1, Button1:1, Move:1, _:1, Wheel:1, WheelNegative:1, Clicks:8>> = <<Flags:16/big>>,
    if Wheel == 1 ->
        SignedClicks = if WheelNegative == 1 -> (0 - Clicks); true -> Clicks end,
        {#ts_inpevt_wheel{point = {X,Y}, clicks = SignedClicks}, Rest};
    true ->
        Action = if Move == 1 -> move; Down == 1 -> down; true -> up end,
        Buttons = if Button3 == 1 -> [3]; true -> [] end ++
                  if Button2 == 1 -> [2]; true -> [] end ++
                  if Button1 == 1 -> [1]; true -> [] end,
        {#ts_inpevt_mouse{point = {X,Y}, action = Action, buttons = Buttons}, Rest}
    end;

decode_ts_inpevt(16#8002, Bin) ->
    <<Flags:16/little, X:16/little, Y:16/little, Rest/binary>> = Bin,
    <<Down:1, _:13, Button5:1, Button4:1>> = <<Flags:16/big>>,
    Action = if Down == 1 -> down; true -> up end,
    Buttons = if Button4 == 1 -> [4]; true -> [] end ++
              if Button5 == 1 -> [5]; true -> [] end,
    {#ts_inpevt_mouse{point = {X,Y}, action = Action, buttons = Buttons}, Rest};

decode_ts_inpevt(_, _) ->
    error(not_implemented).

decode_ts_inpevts(_, <<>>) -> [];
decode_ts_inpevts(0, _) -> [];
decode_ts_inpevts(N, Bin) ->
    <<Time:32/little, Type:16/little, Rest/binary>> = Bin,
    {Next, Rem} = decode_ts_inpevt(Type, Rest),
    [Next | decode_ts_inpevts(N - 1, Rem)].

padding_only(Bin) ->
    Sz = bit_size(Bin),
    <<0:Sz>> = Bin.

decode_ts_shutdown(Bin) ->
    padding_only(Bin),
    #ts_shutdown{}.

decode_ts_input(Bin) ->
    <<N:16/little, _:16, Evts/binary>> = Bin,
    #ts_input{events = decode_ts_inpevts(N, Evts)}.

encode_basic(Rec) ->
    SecFlags = element(2, Rec),
    {Type, Inner} = case Rec of
        #ts_security{} -> {security, encode_ts_security(Rec)};
        #ts_license_vc{} -> {license, encode_ts_license_vc(Rec)};
        #ts_heartbeat{} -> {heartbeat, encode_ts_heartbeat(Rec)};
        #ts_info{} -> {info, encode_ts_info(Rec)}
    end,
    Flags = encode_sec_flags({Type, SecFlags}),
    {ok, <<Flags:16/little, 0:16, Inner/binary>>}.

decode_basic(Bin) ->
    case Bin of
        <<Flags:16/little, _:16, Rest/binary>> ->
            case (catch decode_sec_flags(Flags)) of
                {'EXIT', _} -> {error, badpacket};
                {security, Fl} -> decode_ts_security(Fl, Rest);
                {info, Fl} -> decode_ts_info(Fl, Rest);
                {heartbeat, Fl} -> decode_ts_heartbeat(Fl, Rest);
                {Type, Fl} ->
                    lager:warning("unhandled basic: ~p, flags = ~p", [Type, Fl]),
                    {error, badpacket}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_security(#ts_security{random = Random}) ->
    Len = byte_size(Random),
    <<Len:32/little, Random/binary>>.

encode_ts_license_vc(#ts_license_vc{}) ->
    Inner = <<16#7:32/little, 16#2:32/little, 16#04:16/little, 0:16>>,
    Len = byte_size(Inner) + 4,
    % this was 16#83 before?
    <<16#ff, 16#03, Len:16/little, Inner/binary>>.

decode_ts_security(Fl, Bin) ->
    case Bin of
        <<Length:32/little, Rest/binary>> ->
            RealSize = byte_size(Rest),
            if Length == RealSize ->
                {ok, #ts_security{secflags = Fl, random = Rest}};
            true ->
                {error, badlength}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_heartbeat(#ts_heartbeat{period = Period, warning = Warn, reconnect = Recon}) ->
    <<0, Period, Warn, Recon>>.

decode_ts_heartbeat(Fl, Bin) ->
    case Bin of
        <<_, Period, Warn, Recon>> ->
            {ok, #ts_heartbeat{secflags = Fl, period = Period, warning = Warn, reconnect = Recon}};
        _ ->
            {error, badpacket}
    end.

decode_ts_date(Bin) ->
    <<Year:16/little, Month:16/little, DoW:16/little, Nth:16/little, Hour:16/little, Min:16/little, Sec:16/little, Milli:16/little>> = Bin,
    {{Year, Month, DoW, Nth}, {Hour, Min, Sec, Milli}}.

decode_ts_ext_info(Bin0, SoFar0 = #ts_info{}) ->
    maybe([
        fun(Bin, SoFar) ->
            case Bin of
                <<Af:16/little, Len:16/little, AddrStringZero:Len/binary, Rest/binary>> ->
                    case Af of
                        16#00 ->
                            {continue, [Rest, SoFar]};
                        16#02 ->
                            [AddrString | _] = binary:split(AddrStringZero, <<0>>),
                            {ok, IP} = inet:parse_ipv4_address(binary_to_list(AddrString)),
                            {continue, [Rest, SoFar#ts_info{client_address = IP}]};
                        16#17 ->
                            [AddrString | _] = binary:split(AddrStringZero, <<0>>),
                            {ok, IP} = inet:parse_ipv6_address(binary_to_list(AddrString)),
                            {continue, [Rest, SoFar#ts_info{client_address = IP}]};
                        _ ->
                            {return, {error, {bad_client_af, Af}}}
                    end;
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<Len:16/little, ClientDir:Len/binary, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{client_dir = ClientDir}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<Bias:32/signed-little, NameBin:64/binary, DstEndBin:16/binary, StdBias:32/signed-little, DstNameBin:64/binary, DstStartBin:16/binary, DstBias:32/signed-little, Rest/binary>> ->
                    DstEnd = decode_ts_date(DstEndBin),
                    DstStart = decode_ts_date(DstStartBin),
                    [Name | _] = binary:split(NameBin, <<0, 0>>),
                    [DstName | _] = binary:split(DstNameBin, <<0, 0>>),
                    Tz = #ts_timezone{bias = Bias, name = Name, dst_name = DstName, dst_bias = DstBias, dst_start = DstStart, dst_end = DstEnd},
                    {continue, [Rest, SoFar#ts_info{timezone = Tz}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<SessionId:32/little, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{session_id = SessionId}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<PerfFlags:32/little, Rest/binary>> ->
                    FlagSet = decode_bit_flags(<<PerfFlags:32/big>>, ?ts_info_perf_flags),
                    {continue, [Rest, SoFar#ts_info{perf_flags = sets:to_list(FlagSet)}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<Len:16/little, Cookie:Len/binary, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{reconnect_cookie = Cookie}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<_:16, _:16, Len:16/little, DynTzName:Len/binary, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{dynamic_dst = DynTzName}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<DynDstDisabled:16/little, Rest/binary>> when DynDstDisabled == 0 ->
                    {continue, [Rest, SoFar#ts_info{flags = [dynamic_dst | SoFar#ts_info.flags]}]};
                <<_:16, Rest/binary>> ->
                    {continue, [Rest, SoFar]}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<>> ->
                    {return, {ok, SoFar}};
                _ ->
                    {return, {ok, SoFar#ts_info{extra = Bin}}}
            end
        end
    ], [Bin0, SoFar0]).

decode_ts_info(Fl, Bin) ->
    case Bin of
        <<CodePage:32/little, Flags:32/little, RawDomainLen:16/little, RawUserNameLen:16/little, RawPasswordLen:16/little, RawShellLen:16/little, RawWorkDirLen:16/little, Rest/binary>> ->

            FlagSet = decode_bit_flags(<<Flags:32/big>>, ?ts_info_flags),
            <<_:19, CompLevel:4, _:9>> = <<Flags:32/big>>,

            CompLevelAtom = case CompLevel of
                16#0 -> '8k';
                16#1 -> '64k';
                16#2 -> 'rdp6';
                16#3 -> 'rdp61';
                16#7 -> 'rdp8';
                _ -> CompLevel
            end,

            NullSize = case sets:is_element(unicode, FlagSet) of true -> 2; false -> 1 end,
            DomainLen = RawDomainLen + NullSize,
            UserNameLen = RawUserNameLen + NullSize,
            PasswordLen = RawPasswordLen + NullSize,
            ShellLen = RawShellLen + NullSize,
            WorkDirLen = RawWorkDirLen + NullSize,

            case Rest of
                <<Domain:DomainLen/binary, UserName:UserNameLen/binary, Password:PasswordLen/binary, Shell:ShellLen/binary, WorkDir:WorkDirLen/binary, ExtraInfo/binary>> ->
                    SoFar = #ts_info{secflags = Fl, codepage = CodePage, flags = sets:to_list(FlagSet), compression = CompLevelAtom, domain = Domain, username = UserName, password = Password, shell = Shell, workdir = WorkDir, extra = ExtraInfo},
                    case ExtraInfo of
                        <<>> ->
                            {ok, SoFar};
                        _ ->
                            decode_ts_ext_info(ExtraInfo, SoFar)
                    end;
                _ ->
                    {error, badlength}
            end;
        _ ->
            {error, badpacket}
    end.

maybe_bin(B, _) when is_binary(B) -> B;
maybe_bin(undefined, 1) -> <<0, 0>>;
maybe_bin(undefined, 0) -> <<0>>.

encode_ts_info(#ts_info{codepage = CodePage, flags = FlagAtoms, compression = CompLevelAtom, domain = MaybeDomain, username = MaybeUserName, password = MaybePassword, shell = MaybeShell, workdir = MaybeWorkDir, extra = MaybeExtraInfo}) ->
    Unicode = case lists:member(unicode, FlagAtoms) of true -> 1; _ -> 0 end,
    Domain = maybe_bin(MaybeDomain, Unicode),
    UserName = maybe_bin(MaybeUserName, Unicode),
    Password = maybe_bin(MaybePassword, Unicode),
    Shell = maybe_bin(MaybeShell, Unicode),
    WorkDir = maybe_bin(MaybeWorkDir, Unicode),
    ExtraInfo = maybe_bin(MaybeExtraInfo, Unicode),

    CompLevel = case CompLevelAtom of
        '8k' -> 16#0;
        '64k' -> 16#1;
        'rdp6' -> 16#2;
        'rdp61' -> 16#3;
        'rdp8' -> 16#7;
        I when is_integer(I) -> I
    end,

    <<BeforeComp:19/bitstring, _:4, AfterComp:9/bitstring>> = encode_bit_flags(sets:from_list(FlagAtoms), ?ts_info_flags),
    <<Flags:32/big>> = <<BeforeComp/bitstring, CompLevel:4, AfterComp/bitstring>>,

    NullSize = if Unicode == 1 -> 2; true -> 1 end,
    DomainLen = byte_size(Domain) - NullSize,
    UserNameLen = byte_size(UserName) - NullSize,
    PasswordLen = byte_size(Password) - NullSize,
    ShellLen = byte_size(Shell) - NullSize,
    WorkDirLen = byte_size(WorkDir) - NullSize,

    <<CodePage:32/little, Flags:32/little, DomainLen:16/little, UserNameLen:16/little, PasswordLen:16/little, ShellLen:16/little, WorkDirLen:16/little, Domain/binary, UserName/binary, Password/binary, Shell/binary, WorkDir/binary, ExtraInfo/binary>>.

maybe([], Args) -> error(no_return);
maybe([Fun | Rest], Args) ->
    case apply(Fun, Args) of
        {continue, NewArgs} ->
            maybe(Rest, NewArgs);
        {return, Value} ->
            Value
    end.

