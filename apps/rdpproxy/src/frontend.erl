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
    case db_cookie:get(Cookie) of
        {ok, Sess = #session{
                host = HostBin, port = Port, user = User}} ->
            ok = db_host_meta:put(HostBin, jsxd:thread([
                {set, <<"status">>, <<"busy">>},
                {set, [<<"sessions">>, 0, <<"user">>], User}
            ], [])),
            lager:debug("~p: presented cookie ~p, forwarding to ~p", [S#state.peer, Cookie, HostBin]),
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
    case rdpp:decode_server(Bin) of
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
                    lager:debug("rewriting ts_info: ~p", [TsInfo2#ts_info{extra = snip}]),
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

terminate(_Reason, #state{}) ->
    ok.
