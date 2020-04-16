%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>
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

-module(nms).
-behaviour(gen_server).

-export([start_link/0, stop/1]).
-export([init/1, terminate/2, handle_call/3, handle_info/2]).
-export([handle_cast/2]).

-export([get_user_hosts/2, wol/2, bump_count/3]).

start_link() ->
    gen_server:start_link(?MODULE, [], []).

stop(N) ->
    gen_server:call(N, stop).

get_user_hosts(N, Username) ->
    gen_server:call(N, {get_user_hosts, Username}).

wol(N, Hostname) ->
    gen_server:call(N, {wol, Hostname}).

bump_count(N, Username, Ip) ->
    gen_server:call(N, {bump_count, Username, Ip}).

-record(?MODULE, {gun, host, signer}).

init(_) ->
    NmsConfig = application:get_env(rdpproxy, nms_api, []),
    Host = proplists:get_value(api_host, NmsConfig),
    KeyId = proplists:get_value(key_id, NmsConfig),
    KeyPath = proplists:get_value(privkey_path, NmsConfig),

    {ok, Pem} = file:read_file(KeyPath),
    [KeyEntry] = public_key:pem_decode(Pem),
    Key = public_key:pem_entry_decode(KeyEntry),
    SigKey0 = http_signature_key:from_record(Key),
    SigKey1 = SigKey0#{id := iolist_to_binary([KeyId])},
    Signer = http_signature_signer:new(SigKey1, <<"rsa-sha256">>,
        [<<"date">>, <<"host">>, <<"(request-target)">>]),

    {ok, Gun} = gun:open(Host, 443),

    {ok, #?MODULE{gun = Gun, host = Host, signer = Signer}}.

terminate(_Reason, _S = #?MODULE{gun = Gun}) ->
    gun:close(Gun),
    ok.

handle_info(_Info, S = #?MODULE{}) ->
    {noreply, S}.

handle_cast(_, S = #?MODULE{}) ->
    {noreply, S}.

do_signed_req(Method, Uri, Params, #?MODULE{gun = Gun, host = Host, signer = Signer}) ->
    Hdrs0 = #{<<"host">> => Host},
    Hdrs1 = case Method of
        get -> Hdrs0;
        _ -> Hdrs0#{<<"content-type">> => <<"application/x-www-form-urlencoded">>}
    end,
    MethodBin = string:uppercase(atom_to_binary(Method, utf8)),
    Body = case Method of
        post ->
            Qs = uri_string:compose_query(maps:to_list(Params)),
            iolist_to_binary([Qs]);
        _ -> <<>>
    end,
    SReq = http_signature:sign(Signer, Method, Uri, Hdrs1),
    #{headers := Hdrs2} = SReq,
    Req = gun:request(Gun, MethodBin, Uri, maps:to_list(Hdrs2), Body),
    case gun:await(Gun, Req, 2000) of
        {response, fin, Status, _Headers} ->
            {ok, Status};
        {response, nofin, Status, Headers} ->
            RHdrs = maps:from_list(Headers),
            {ok, Body0} = gun:await_body(Gun, Req),
            Body1 = case RHdrs of
                #{<<"content-type">> := <<"application/json">>} ->
                    jsx:decode(Body0, [return_maps]);
                _ -> Body0
            end,
            {ok, Status, Body1};
        Else -> Else
    end.

handle_call({wol, Hostname}, _From, S = #?MODULE{}) ->
    Uri = <<"/api/wol.php">>,
    case do_signed_req(post, Uri, #{<<"hosts">> => Hostname}, S) of
        {ok, 200, Data} ->
            Lines = binary:split(Data, [<<"\n">>], [global]),
            {reply, {ok, Lines}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call({get_user_hosts, User}, _From, S = #?MODULE{}) ->
    Uri = iolist_to_binary([<<"/api/userhost.php/">>, User]),
    case do_signed_req(get, Uri, #{}, S) of
        {ok, 200, Hosts} -> {reply, {ok, Hosts}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call({bump_count, User, Ip}, _From, S = #?MODULE{}) ->
    Uri = iolist_to_binary([<<"/api/rdpcount.php/">>, User, $/, Ip]),
    case do_signed_req(post, Uri, #{<<"submit">> => <<"true">>}, S) of
        {ok, 200, Reply} -> {reply, {ok, Reply}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call(stop, _From, S = #?MODULE{}) ->
    {stop, normal, ok, S}.
