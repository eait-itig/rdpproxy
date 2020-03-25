%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(frontend).
-behaviour(rdp_server).

-include_lib("rdp_proto/include/rdp_server.hrl").

-include("session.hrl").

-export([
    init/1,
    handle_connect/4,
    init_ui/2,
    handle_event/3,
    handle_raw_data/3,
    terminate/2
    ]).

-record(state, {
    peer :: term(),
    session :: #session{} | undefined,
    subs = [] :: [pid()],
    backend :: pid(),
    intercept = true :: boolean()
    }).

init(Peer) ->
    {ok, #state{peer = Peer}}.

handle_connect(Cookie, _Protocols, Srv, S = #state{}) ->
    case cookie_ra:get(Cookie) of
        {ok, Sess = #session{
                host = HostBin, port = Port, user = User}} ->
            lager:debug("~p: presented cookie ~p (~p), forwarding to ~p",
                [S#state.peer, Cookie, User, HostBin]),
            {ok, Backend} = backend:start_link(Srv, binary_to_list(HostBin), Port),
            ok = rdp_server:watch_child(Srv, Backend),
            {accept_raw, S#state{session = Sess, backend = Backend}};

        _ ->
            SslOpts = rdpproxy:config([frontend, ssl_options], [
                {certfile, "etc/cert.pem"},
                {keyfile, "etc/key.pem"}]),
            {accept, SslOpts, S}
    end.

init_ui(Srv, S = #state{subs = []}) ->
    {ok, Ui} = ui_fsm_sup:start_ui(Srv),
    lager:debug("frontend spawned ui_fsm ~p", [Ui]),
    {ok, S}.

handle_event({subscribe, Pid}, _Srv, S = #state{subs = Subs}) ->
    {ok, S#state{subs = [Pid | Subs]}};

handle_event(Event, Srv, S = #state{subs = Subs}) ->
    lists:foreach(fun(Sub) ->
        gen_fsm:send_event(Sub, {input, Srv, Event})
    end, Subs),
    {ok, S}.

handle_raw_data(Data, _Srv, S = #state{intercept = false, backend = B}) ->
    gen_fsm:send_event(B, {frontend_data, Data}),
    {ok, S};
handle_raw_data(Bin, _Srv, S = #state{intercept = true, backend = B}) ->
    %debug_print_data(Bin),
    case rdpp:decode_server(Bin) of
        %
        % Certain clients (like FreeRDP) with GFX enabled will learn during
        % the login screen session that 32bpp colour isn't supported. They will
        % then try to ask the backend server here for GFX/H264 without 32bpp
        % colour, which causes a reject from the MS RDP server.
        %
        % If we see someone trying GFX but without 32bpp colour, add it back
        % into their TSUDs.
        %
        {ok, {mcs_pdu, McsCi = #mcs_ci{}}, Rem} ->
            {ok, Tsuds0} = tsud:decode(McsCi#mcs_ci.data),

            TsudCore0 = lists:keyfind(tsud_core, 1, Tsuds0),
            Colors0 = TsudCore0#tsud_core.colors,
            Caps0 = TsudCore0#tsud_core.capabilities,

            TsudCluster0 = lists:keyfind(tsud_cluster, 1, Tsuds0),
            #state{session = Sess} = S,
            SessId = cookie_ra:session_id(Sess),
            #tsud_cluster{sessionid = TheirSessId} = TsudCluster0,

            MatchesSessId = (SessId == TheirSessId),
            HasGfx = lists:member(dynvc_gfx, Caps0),
            Has32Bpp = lists:member('32bpp', Colors0),

            lager:debug("core tsud: ~s", [tsud:pretty_print(TsudCore0)]),
            lager:debug("cluster tsud: ~s", [tsud:pretty_print(TsudCluster0)]),

            case {MatchesSessId, HasGfx, Has32Bpp} of
                {false, _, _} ->
                    lager:warning("closing connection due to sessid mismatch "
                        "(ours = ~p, they sent = ~p)", [SessId, TheirSessId]),
                    {stop, bad_session_id, S};
                {true, true, false} ->
                    % Remove the redirection info while we're here.
                    TsudCluster1 = TsudCluster0#tsud_cluster{sessionid = none},
                    lager:debug("rewriting client tsud: ~s", [tsud:pretty_print(TsudCluster1)]),
                    Tsuds1 = lists:keyreplace(tsud_cluster, 1, Tsuds0, TsudCluster1),

                    PrefColor0 = TsudCore0#tsud_core.color,
                    Colors1 = ['32bpp' | Colors0],
                    Color1 = '32bpp',
                    Caps1 = ['want_32bpp' | Caps0],
                    TsudCore1 = TsudCore0#tsud_core{colors = Colors1, color = Color1, capabilities = Caps1},
                    lager:debug("rewriting client tsud: ~s", [tsud:pretty_print(TsudCore1)]),
                    Tsuds2 = lists:keyreplace(tsud_core, 1, Tsuds1, TsudCore1),

                    TsudsBin1 = lists:foldl(fun(Tsud, SoFar) ->
                        {ok, TsudBin} = tsud:encode(Tsud),
                        <<SoFar/binary, TsudBin/binary>>
                    end, <<>>, Tsuds2),
                    {ok, OutCiData} = mcsgcc:encode_ci(McsCi#mcs_ci{data = TsudsBin1}),
                    {ok, OutDtData} = x224:encode(#x224_dt{data = OutCiData}),
                    {ok, OutPkt} = tpkt:encode(OutDtData),
                    gen_fsm:send_event(B, {frontend_data, <<OutPkt/binary, Rem/binary>>}),
                    {ok, S};
                _ ->
                    gen_fsm:send_event(B, {frontend_data, Bin}),
                    {ok, S}
            end;
        %
        % The last thing we have to rewrite before we can just be a data shovel
        % is the ts_info PDU. Here we'll forcibly inject the domain, username
        % and pw from the cookie.
        %
        {ok, {mcs_pdu, McsData = #mcs_data{data = RdpData0}}, Rem} ->
            case rdpp:decode_basic(RdpData0) of
                {ok, TsInfo0 = #ts_info{secflags = []}} ->
                    #state{session = #session{user = User, password = Password, domain = Domain}} = S,
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
                    lager:debug("rewriting ts_info: ~s", [rdpp:pretty_print(TsInfo2#ts_info{password = snip, extra = snip})]),
                    {ok, RdpData1} = rdpp:encode_basic(TsInfo2),
                    {ok, McsOutBin} = mcsgcc:encode_dpdu(McsData#mcs_data{data = RdpData1}),
                    {ok, X224OutBin} = x224:encode(#x224_dt{data = McsOutBin}),
                    {ok, OutBin} = tpkt:encode(X224OutBin),
                    gen_fsm:send_event(B, {frontend_data, <<OutBin/binary, Rem/binary>>}),
                    {ok, S#state{intercept = false}};

                _ ->
                    gen_fsm:send_event(B, {frontend_data, Bin}),
                    {ok, S}
            end;

        _ ->
            gen_fsm:send_event(B, {frontend_data, Bin}),
            {ok, S}
    end.

debug_print_data(<<>>) -> ok;
debug_print_data(Bin) ->
    case rdpp:decode_server(Bin) of
        {ok, {fp_pdu, _Pdu}, Rem} ->
            %error_logger:info_report(["frontend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
            debug_print_data(Rem);
        {ok, {x224_pdu, Pdu}, Rem} ->
            lager:info("frontend rx x224: ~s", [x224:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu = #mcs_srv_data{data = RdpData, channel = _Chan}}, Rem} ->
            case rdpp:decode_basic(RdpData) of
                {ok, Rec} ->
                    {ok, RdpData} = rdpp:encode_basic(Rec),
                    lager:info("frontend rx rdp_basic: ~s", [rdpp:pretty_print(Rec)]);
                _ ->
                    case rdpp:decode_sharecontrol(RdpData) of
                        {ok, #ts_demand{} = Rec} ->
                            case rdpp:encode_sharecontrol(Rec) of
                                {ok, RdpData} -> ok;
                                {ok, OtherData} ->
                                    file:write_file("backend_orig", RdpData),
                                    file:write_file("backend_reenc", OtherData),
                                    lager:info("original data = ~p, reenc data = ~p", [RdpData, OtherData]);
                                _ -> error(fail_reencode)
                            end,
                            lager:info("frontend rx rdp_sharecontrol: ~s", [rdpp:pretty_print(Rec)]);
                        {ok, Rec} ->
                            lager:info("frontend rx rdp_sharecontrol: ~s", [rdpp:pretty_print(Rec)]);
                        _ ->
                            lager:info("frontend rx mcs: ~s", [mcsgcc:pretty_print(Pdu)])
                    end
            end,
            debug_print_data(Rem);
        {ok, {mcs_pdu, McsCi = #mcs_ci{}}, Rem} ->
            {ok, Tsuds} = tsud:decode(McsCi#mcs_ci.data),
            lager:info("frontend rx ci with tsuds: ~s", [tsud:pretty_print(Tsuds)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, McsCr = #mcs_cr{}}, Rem} ->
            {ok, Tsuds} = tsud:decode(McsCr#mcs_cr.data),
            lager:info("frontend rx cr with tsuds: ~s", [tsud:pretty_print(Tsuds)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, #mcs_tir{}}, Rem} ->
            {ok, Data, _} = tpkt:decode(Bin),
            {ok, X224Pdu} = x224:decode(Data),
            lager:info("decode_cr: ~p, data: ~p", [mcsgcc:decode_cr(X224Pdu#x224_dt.data), Bin]),
            file:write_file("bad_cr", Bin),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu}, Rem} ->
            lager:info("frontend rx mcs: ~s", [mcsgcc:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, Something, Rem} ->
            lager:info("frontend unknown: ~p, rem = ~p", [Something, Rem]);
        {error, Reason} ->
            lager:info("frontend parse err: ~p", [Reason]),
            ok
    end.

terminate(_Reason, #state{}) ->
    ok.
