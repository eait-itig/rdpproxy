%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(frontend).
-behaviour(gen_fsm).

-include_lib("rdp_proto/include/x224.hrl").
-include_lib("rdp_proto/include/mcsgcc.hrl").
-include_lib("rdp_proto/include/kbd.hrl").
-include_lib("rdp_proto/include/tsud.hrl").
-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/fastpath.hrl").
-include_lib("rdp_proto/include/cliprdr.hrl").

-include("session.hrl").

-export([start_link/2]).
-export([accept/2, initiation/2, mcs_connect/2, mcs_attach_user/2, mcs_chans/2, rdp_clientinfo/2, rdp_capex/2, init_finalize/2, run_ui/2, run_ui/3, proxy/2, proxy_intercept/2, wait_proxy/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Sock :: term(), Sup :: pid()) -> {ok, pid()}.
start_link(Sock, Sup) ->
    gen_fsm:start_link(?MODULE, [Sock, Sup], []).

-record(x224_state, {us=none, them=none}).
-record(mcs_state, {us=none, them=none, iochan=none, msgchan=none, chans=[]}).
-record(data, {lsock, sock, sup, unused, uis=[], sslsock=none, backsock=none, chansavail=[], backend=none, queue=[], waitchans=[], tsud_core={}, tsuds=[], caps=[], askedfor=[], shareid=0, x224=#x224_state{}, mcs=#mcs_state{}, session, client_info, peer, bpp}).

hexdump(Offset, []) -> ok;
hexdump(Offset, Bytes) ->
    {ThisLine,Rest} = if
        (length(Bytes) > 16) -> lists:split(16, Bytes);
        true -> {Bytes, []}
    end,
    io:format("~4.16.0B   ~s\n", [Offset, string:join(ThisLine, " ")]),
    hexdump(Offset + length(ThisLine), Rest).
hexdump(B) ->
    hexdump(0, [io_lib:format("~2.16.0B",[X]) || <<X:8>> <= B]).

send_dpdu(SslSock, McsPkt) ->
    {ok, McsData} = mcsgcc:encode_dpdu(McsPkt),
    {ok, DtData} = x224:encode(#x224_dt{data = McsData}),
    {ok, Packet} = tpkt:encode(DtData),
    ok = ssl:send(SslSock, Packet).

send_update(Data = #data{sslsock = SslSock, caps = Caps}, TsUpdate) ->
    #ts_cap_general{flags = Flags} = lists:keyfind(ts_cap_general, 1, Caps),
    case lists:member(fastpath, Flags) of
        true ->
            Bin = fastpath:encode_output(#fp_pdu{flags=[salted_mac], contents=[TsUpdate]}),
            ok = ssl:send(SslSock, Bin);
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
    case inet:peername(Sock) of
        {ok, Peer} ->
            {next_state, initiation, D#data{sock = Sock, peer = Peer}};
        _ ->
            {next_state, initiation, D#data{sock = Sock, peer = unknown}}
    end.

initiation({x224_pdu, #x224_cr{class = 0, dst = 0} = Pkt}, #data{sock = Sock, x224 = X224} = Data) ->
    #x224_cr{src = ThemRef, rdp_cookie = Cookie, rdp_protocols = Protos} = Pkt,

    NewX224 = X224#x224_state{them = ThemRef},
    NewData = Data#data{x224 = NewX224, askedfor=Protos},
    HasSsl = lists:member(ssl, Protos),

    if HasSsl ->
        case db_cookie:get(Cookie) of
            {ok, Sess = #session{host = HostBin, port = Port, user = User}} ->
                ok = db_host_meta:put(HostBin, jsxd:thread([
                        {set, <<"status">>, <<"busy">>},
                        {set, [<<"sessions">>, 0, <<"user">>], User}
                    ], [])),
                lager:debug("~p: presented cookie ~p, forwarding to ~p", [Data#data.peer, Cookie, HostBin]),
                {ok, Backend} = backend:start_link(self(), binary_to_list(HostBin), Port, Pkt),
                {next_state, wait_proxy, NewData#data{backend = Backend, session = Sess}};

            _ ->
                UsRef = 1000 + random:uniform(1000),
                Resp = #x224_cc{src = UsRef, dst = ThemRef, rdp_selected = [ssl], rdp_flags = [extdata,dynvc_gfx]},
                {ok, RespData} = x224:encode(Resp),
                {ok, Packet} = tpkt:encode(RespData),
                inet:setopts(Sock, [{packet, raw}]),
                gen_tcp:send(Sock, Packet),

                Ciphers = [{A,B,C}||{A,B,C}<-ssl:cipher_suites(),not (B =:= des_cbc),not (C =:= md5)],
                Ret = ssl:ssl_accept(Sock,
                    [{ciphers, Ciphers}, {honor_cipher_order, true} |
                    rdpproxy:config([frontend, ssl_options], [
                        {certfile, "etc/cert.pem"},
                        {keyfile, "etc/key.pem"}])]),
                case Ret of
                    {ok, SslSock} ->
                        {ok, {Ver, Cipher}} = ssl:connection_info(SslSock),
                        lager:info("~p: accepted tls ~p, cipher = ~p", [Data#data.peer, Ver, Cipher]),
                        ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),
                        {next_state, mcs_connect, NewData#data{x224 = NewX224#x224_state{us = UsRef}, sslsock = SslSock}};
                    {error, closed} ->
                        {stop, normal, NewData};
                    {error, Err} ->
                        lager:debug("~p: tls error: ~p, dropping connection", [Data#data.peer, Err]),
                        {stop, normal, NewData}
                end
        end;
    true ->
        lager:debug("~p rejecting cr, protocols = ~p", [Data#data.peer, Protos]),
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
            {continue, [D#data{tsuds = Tsuds}, Tsuds, <<>>]}
        end,
        fun(D, Tsuds, SoFar) ->
            % allocate our MCS user
            {MyUser, D2} = next_channel(D, 1002),
            {ThemUser, D3} = next_channel(D2, 1007),
            Mcs = D3#data.mcs,
            D4 = D3#data{mcs = Mcs#mcs_state{us = MyUser, them = ThemUser}},
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
                            _ ->
                                {C, DD2} = next_channel(DD),
                                Mcs0 = DD2#data.mcs,
                                Mcs1 = Mcs0#mcs_state{
                                    chans = [{C, Chan} | Mcs0#mcs_state.chans]},
                                DD3 = DD2#data{mcs = Mcs1},
                                {DD3, [C | Cs]}%;
                            %_ ->
                            %    {DD, [0 | Cs]}
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
        %   case lists:keyfind(tsud_multitransport, 1, Tsuds) of
        %       false ->
        %           {continue, [D, Tsuds, SoFar]};
        %       _ ->
        %           {ok, Bin} = tsud:encode(#tsud_svr_multitransport{}),
        %           {continue, [D, Tsuds, <<SoFar/binary, Bin/binary>>]}
        %   end
        %end,
        fun(D = #data{mcs = Mcs}, Tsuds, SvrTsuds) ->
            {ok, Cr} = mcsgcc:encode_cr(#mcs_cr{data = SvrTsuds, node = Mcs#mcs_state.us}),

            %{ok, DebugCr} = mcsgcc:decode_cr(Cr),
            %{ok, DebugTsuds} = tsud:decode(SvrTsuds),
            %error_logger:info_report(["tsud output: ", tsud:pretty_print(DebugTsuds)]),
            %error_logger:info_report(["cr output: ", mcsgcc:pretty_print(DebugCr)]),

            {ok, DtData} = x224:encode(#x224_dt{data = Cr}),
            {ok, Packet} = tpkt:encode(DtData),
            ok = ssl:send(SslSock, Packet),

            TsCore = lists:keyfind(tsud_core, 1, Tsuds),
            {return, {next_state, mcs_attach_user, D#data{tsud_core = TsCore}}}
        end
    ], [Data0]);

mcs_connect({mcs_pdu, Pdu}, Data) ->
    lager:info("mcs_connect got: ~s", [mcsgcc:pretty_print(Pdu)]),
    {next_state, mcs_connect, Data}.

mcs_attach_user({x224_pdu, _}, Data) ->
    {next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_edr{}}, Data) ->
    {next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_aur{}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them}} = Data) ->
    send_dpdu(SslSock, #mcs_auc{user = Them, status = 'rt-successful'}),
    {next_state, mcs_chans, Data};

mcs_attach_user({mcs_pdu, Pdu}, Data) ->
    lager:info("mcs_attach_user got: ~s", [mcsgcc:pretty_print(Pdu)]),
    {next_state, mcs_attach_user, Data}.

mcs_chans({mcs_pdu, #mcs_cjr{user = Them, channel = Chan}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them, us = Us}, waitchans = Chans} = Data) ->

    NewChans = Chans -- [Chan],
    NewData = Data#data{waitchans = NewChans},

    send_dpdu(SslSock, #mcs_cjc{user = Us, channel = Chan, status = 'rt-successful'}),

    if (length(NewChans) == 0) ->
        lager:info("~p mcs_chans all ok (chans = ~p)", [Data#data.peer, NewData#data.mcs#mcs_state.chans]),
        {next_state, rdp_clientinfo, NewData};
    true ->
        {next_state, mcs_chans, NewData}
    end;

mcs_chans({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan} = Pdu}, #data{waitchans = Chans, mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}} = Data) ->
    case rdpp:decode_basic(RdpData) of
        {ok, #ts_info{}} ->
            lager:info("got ts_info while still waiting for chans (missing = ~p)", [Chans]),
            rdp_clientinfo({mcs_pdu, Pdu}, Data);
        {ok, RdpPkt} ->
            lager:info("mcs_chans got: ~s", [rdpp:pretty_print(RdpPkt)]),
            {next_state, mcs_chans, Data};
        _ ->
            lager:info("mcs_chans got: ~s", [mcsgcc:pretty_print(Pdu)]),
            {next_state, mcs_chans, Data}
    end;

mcs_chans({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = Them} = Pdu}, #data{mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}} = Data) ->
    case rdpp:decode_basic(RdpData) of
        {ok, RdpPkt} ->
            lager:info("mcs_chans got on user chan: ~s", [rdpp:pretty_print(RdpPkt)]);
        _ ->
            lager:info("mcs_chans got on user chan: ~s", [mcsgcc:pretty_print(Pdu)])
    end,
    {next_state, mcs_chans, Data}.

rdp_clientinfo({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them, us = Us, iochan = IoChan}} = Data) ->
    case rdpp:decode_basic(RdpData) of
        {ok, #ts_info{} = InfoPkt} ->
            {ok, LicData} = rdpp:encode_basic(#ts_license_vc{secflags=[encrypt_license]}),
            send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = LicData}),

            Core = Data#data.tsud_core,
            {Bpp,Format} = case Core#tsud_core.color of
                '16bpp' -> {16, '16bpp'};
                _ ->
                    case lists:member('24bpp', Core#tsud_core.colors) of
                        true -> {24, '24bpp'};
                        false -> {16, '16bpp'}
                    end
            end,
            true = lists:member(Format, Core#tsud_core.colors),
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
                        #ts_cap_bitmap_codec{codec = nscodec, id = 1, properties = [{dynamic_fidelity, true}, {subsampling, true}, {color_loss_level, 3}]}
                    ]},
                    #ts_cap_bitmap{bpp = 24, width = Core#tsud_core.width, height = Core#tsud_core.height, flags = [resize,compression,dynamic_bpp,skip_alpha,multirect]},
                    #ts_cap_order{},
                    #ts_cap_pointer{},
                    #ts_cap_input{flags = [mousex, scancodes, unicode, fastpath, fastpath2], kbd_layout = 0, kbd_type = 0, kbd_fun_keys = 0},
                    #ts_cap_multifrag{maxsize = 4*1024*1024},
                    #ts_cap_large_pointer{},
                    #ts_cap_colortable{},
                    #ts_cap_surface{}
                ]
            }),
            %file:write_file("my_demand", DaPkt),
            %{ok, Da} = rdpp:decode_sharecontrol(DaPkt),
            %error_logger:info_report(["sending demand packet: ", rdpp:pretty_print(Da)]),
            send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = DaPkt}),

            {next_state, rdp_capex, Data#data{shareid = ShareId, client_info = InfoPkt, bpp = Bpp}};
        {ok, RdpPkt} ->
            lager:info("rdp packet: ~s", [rdpp:pretty_print(RdpPkt)]),
            {next_state, rdp_clientinfo, Data};
        Other ->
            {stop, {bad_protocol, Other}, Data}
    end;

rdp_clientinfo({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = Them} = Pdu}, #data{mcs = #mcs_state{us = Us, them = Them, iochan = IoChan}} = Data) ->
    case rdpp:decode_basic(RdpData) of
        {ok, RdpPkt} ->
            lager:info("rdp_clientinfo got on user chan: ~s", [rdpp:pretty_print(RdpPkt)]);
        _ ->
            lager:info("rdp_clientinfo got on user chan: ~s", [mcsgcc:pretty_print(Pdu)])
    end,
    {next_state, rdp_clientinfo, Data}.

rdp_capex({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, #data{sslsock = SslSock, mcs = #mcs_state{them = Them, iochan = IoChan}, shareid = ShareId} = Data) ->
    case rdpp:decode_sharecontrol(RdpData) of
        {ok, #ts_confirm{shareid = ShareId, capabilities = Caps} = Pkt} ->
            {next_state, init_finalize, Data#data{caps = Caps}};
        {ok, RdpPkt} ->
            %lager:info("rdp_capex got ~s", [rdpp:pretty_print(RdpPkt)]),
            {next_state, rdp_capex, Data};
        Wat ->
            case rdpp:decode_ts_confirm(1, RdpData) of
                #ts_confirm{shareid = ShareId, capabilities = Caps} = Pkt ->
                    {next_state, init_finalize, Data#data{caps = Caps}};
                Wat2 ->
                    lager:error("~p WAT: ~p => ~p then ~p", [Data#data.peer, RdpData, Wat, Wat2]),
                    % lolwut bro
                    {next_state, rdp_capex, Data}
            end
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

            {ok, Ui} = ui_fsm_sup:start_ui(self()),
            lager:debug("frontend for ~p spawned ui_fsm ~p", [Data#data.peer, Ui]),
            % send_update(Data, #ts_update_orders{orders = [
            %     #ts_order_opaquerect{dest = {0,0}, size = {100,100}, color = {100,100,100}}]}),
            % Bitmap = << <<I:16/big>> || I <- lists:seq(1,64*64) >>,
            % send_update(Data, #ts_update_bitmaps{bitmaps = [
            %     #ts_bitmap{dest = {100,100}, size = {64,64}, bpp=16, data = Bitmap}]}),
            {next_state, run_ui, Data};

        {ok, #ts_sharedata{} = SD} ->
            {next_state, init_finalize, Data};

        {ok, RdpPkt} ->
            {next_state, rdp_capex, Data}

    end.

run_ui(get_canvas, From, D = #data{caps = Caps, bpp = Bpp}) ->
    #ts_cap_bitmap{width = W, height = H} = lists:keyfind(ts_cap_bitmap, 1, Caps),
    gen_fsm:reply(From, {W, H, Bpp}),
    {next_state, run_ui, D};

run_ui(get_redir_support, From, D = #data{tsuds = Tsuds}) ->
    case lists:keyfind(tsud_cluster, 1, Tsuds) of
        #tsud_cluster{flags = Flags, version = V} when V >= 4 ->
            gen_fsm:reply(From, lists:member(supported, Flags));
        _ ->
            gen_fsm:reply(From, false)
    end,
    {next_state, run_ui, D};

run_ui(get_autologon, From, D = #data{client_info = TsInfo}) ->
    #ts_info{flags = Flags, username = U0, domain = Do0, password = P0} = TsInfo,
    Unicode = lists:member(unicode, Flags),
    NullLen = if Unicode -> 2; not Unicode -> 1 end,
    U1 = binary:part(U0, {0, byte_size(U0) - NullLen}),
    Do1 = binary:part(Do0, {0, byte_size(Do0) - NullLen}),
    P1 = binary:part(P0, {0, byte_size(P0) - NullLen}),
    U2 = if Unicode -> unicode:characters_to_binary(U1, {utf16,little}, utf8); not Unicode -> U1 end,
    [U3 | _] = binary:split(U2, <<0>>),
    Do2 = if Unicode -> unicode:characters_to_binary(Do1, {utf16,little}, utf8); not Unicode -> Do1 end,
    [Do3 | _] = binary:split(Do2, <<0>>),
    P2 = if Unicode -> unicode:characters_to_binary(P1, {utf16,little}, utf8); not Unicode -> P1 end,
    [P3 | _] = binary:split(P2, <<0>>),
    case lists:member(autologon, Flags) of
        true -> gen_fsm:reply(From, {true, U3, Do3, P3});
        false -> gen_fsm:reply(From, {false, U3, Do3, P3})
    end,
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

    lager:debug("sending deactivate and close"),
    {ok, Deact} = rdpp:encode_sharecontrol(#ts_deactivate{channel = Us, shareid = ShareId}),
    send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Deact}),
    ssl:close(SslSock),
    {stop, normal, D};

run_ui(close, D = #data{sslsock = SslSock, mcs = #mcs_state{us = Us, iochan = IoChan}, shareid = ShareId}) ->
    lager:debug("sending deactivate and close"),
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

run_ui({mcs_pdu, #mcs_data{user = Them, data = RdpData, channel = IoChan}}, D = #data{mcs = #mcs_state{them = Them, us = Us, iochan = IoChan}, shareid = ShareId, sslsock = SslSock, uis = Uis}) ->
    case rdpp:decode_sharecontrol(RdpData) of
        {ok, #ts_sharedata{shareid = ShareId, data = #ts_input{events = Evts}}} ->
            lists:foreach(fun(Evt) ->
                lists:foreach(fun(Ui) ->
                    gen_fsm:send_event(Ui, {input, self(), Evt})
                end, Uis)
            end, Evts),
            {next_state, run_ui, D};

        {ok, #ts_sharedata{shareid = ShareId, data = #ts_shutdown{}}} ->
            {ok, Deact} = rdpp:encode_sharecontrol(#ts_deactivate{channel = Us, shareid = ShareId}),
            send_dpdu(SslSock, #mcs_srv_data{user = Us, channel = IoChan, data = Deact}),
            ssl:close(SslSock),
            {stop, normal, D};

        {ok, #ts_sharedata{} = SD} ->
            {next_state, run_ui, D};

        {ok, RdpPkt} ->
            {next_state, rdp_capex, D}
    end;

run_ui({mcs_pdu, #mcs_data{user = Them, data = Data, channel = Chan}}, D = #data{mcs = #mcs_state{them = Them, us = Us, chans = Chans}}) ->
    ChanName = case proplists:get_value(Chan, Chans) of
        undefined ->
            lager:warning("run_ui got data on unknown vchannel ~p: ~p", [Chan, Data]),
            {next_state, run_ui, D};

        #tsud_net_channel{name = Name} ->
            case rdpp:decode_vchan(Data) of
                {ok, VPkt = #ts_vchan{flags = VFlags, data = VData}} ->
                    case string:to_lower(Name) of
                        "cliprdr" ->
                            case cliprdr:decode(VData) of
                                {ok, ClipPdu} ->
                                    lager:debug("cliprdr: ~s", [cliprdr:pretty_print(ClipPdu)]),
                                    {next_state, run_ui, D};
                                Err ->
                                    lager:warning("cliprdr decode failed: ~p (~s)", [Err, rdpp:pretty_print(VPkt)]),
                                    {next_state, run_ui, D}
                            end;
                        _ ->
                            lager:warning("unhandled data on vchannel ~p (~p): ~s", [Name, Chan, rdpp:pretty_print(VPkt)]),
                            {next_state, run_ui, D}
                    end;
                _ ->
                    lager:warning("run_ui got invalid data on vchannel ~p (~p): ~p", [Name, Chan, Data]),
                    {next_state, run_ui, D}
            end
    end;

run_ui({x224_pdu, #x224_dr{}}, D = #data{sslsock = SslSock}) ->
    ssl:close(SslSock),
    {stop, normal, D}.

wait_proxy({data, Bin}, #data{queue = Queue} = Data) ->
    {next_state, wait_proxy, Data#data{queue = Queue ++ [Bin]}};

wait_proxy({backend_ready, Backend, Backsock, TheirCC}, #data{queue = Queue, backend = Backend, x224 = #x224_state{them = ThemRef}, sock = Sock} = Data) ->
    lager:debug("frontend send cc: ~p", [TheirCC]),
    {ok, RespData} = x224:encode(TheirCC),
    {ok, Packet} = tpkt:encode(RespData),
    gen_tcp:send(Sock, Packet),

    inet:setopts(Sock, [{packet, raw}]),
    Ciphers = [{A,B,C}||{A,B,C}<-ssl:cipher_suites(),not (B =:= des_cbc),not (C =:= md5)],
    {ok, SslSock} = ssl:ssl_accept(Sock,
                [{ciphers, Ciphers}, {honor_cipher_order, true} |
                    rdpproxy:config([frontend, ssl_options], [
                        {certfile, "etc/cert.pem"},
                        {keyfile, "etc/key.pem"}])]),
    ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),
    lists:foreach(fun(Bin) ->
        ssl:send(Backsock, Bin)
        %gen_fsm:send_event(Backend, {frontend_data, self(), Bin})
    end, Queue),
    {next_state, proxy_intercept, Data#data{queue = [], backsock = Backsock, sslsock = SslSock}}.

proxy_intercept({data, Bin}, #data{sslsock = SslSock, backsock = Backsock, backend = Backend} = Data) ->
    case rdpp:decode_server(Bin) of
        {ok, {mcs_pdu, McsData = #mcs_data{data = RdpData0}}, Rem} ->
            case rdpp:decode_basic(RdpData0) of
                {ok, TsInfo0 = #ts_info{secflags = []}} ->
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
                    lager:debug("rewriting ts_info: ~p", [TsInfo2#ts_info{extra = snip}]),
                    {ok, RdpData1} = rdpp:encode_basic(TsInfo2),
                    {ok, McsOutBin} = mcsgcc:encode_dpdu(McsData#mcs_data{data = RdpData1}),
                    {ok, X224OutBin} = x224:encode(#x224_dt{data = McsOutBin}),
                    {ok, OutBin} = tpkt:encode(X224OutBin),
                    ssl:send(Backsock, <<OutBin/binary, Rem/binary>>),
                    {next_state, proxy, Data};

                _ ->
                    ssl:send(Backsock, Bin),
                    {next_state, proxy_intercept, Data}
            end;

        _ ->
            ssl:send(Backsock, Bin),
            {next_state, proxy_intercept, Data}
    end;

proxy_intercept({backend_data, Backend, Bin}, #data{sslsock = SslSock, backend = Backend} = Data) ->
    ssl:send(SslSock, Bin),
    {next_state, proxy_intercept, Data}.

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
            Name = filename:join(["/tmp", base64:encode(crypto:rand_bytes(6))]),
            file:write_file(Name, Bin),
            lager:warning("~p connseq decode fail in ~p: ~p (data saved in ~p)", [Data#data.peer, State, Reason, Name]),
            {next_state, State, Data}
    end;
handle_info({tcp, Sock, Bin}, State, #data{sock = Sock} = Data) ->
    case rdpp:decode_server(Bin) of
        {ok, Evt, Rem} ->
            queue_remainder(Sock, Rem),
            ?MODULE:State(Evt, Data);
        {error, Reason} ->
            Name = filename:join(["/tmp", base64:encode(crypto:rand_bytes(6))]),
            file:write_file(Name, Bin),
            lager:warning("~p decode fail in ~p: ~p (data saved in ~p)", [Data#data.peer, State, Reason, Name]),
            {next_state, State, Data}
    end;

handle_info({ssl, SslSock, Bin}, State, #data{sslsock = SslSock} = Data)
        when (State =:= proxy) orelse (State =:= proxy_intercept) orelse (State =:= wait_proxy) ->
    ?MODULE:State({data, Bin}, Data);

handle_info({ssl, SslSock, Bin}, State, #data{sock = Sock, sslsock = SslSock} = Data) ->
    handle_info({tcp, Sock, Bin}, State, Data);

handle_info({ssl_closed, Sock}, State, #data{sock = Sock} = Data) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ -> lager:debug("ssl closed by remote side")
    end,
    {stop, normal, Data};

handle_info({tcp_closed, Sock}, State, #data{sock = Sock} = Data) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ -> lager:debug("tcp closed by remote side")
    end,
    {stop, normal, Data};
    %?MODULE:State(disconnect, Data);

handle_info(_Msg, State, Data) ->
    {next_state, State, Data}.

%% @private
terminate(Reason, State, Data = #data{peer = P}) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ -> lager:debug("frontend terminating due to ~p, was connected to ~p", [Reason, P])
    end,
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
