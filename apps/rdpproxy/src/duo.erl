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

-module(duo).
-behaviour(gen_server).

-export([start_link/0, stop/1]).
-export([init/1, terminate/2, handle_call/3, handle_info/2]).

-export([preauth/2, auth/2, auth_status/2]).

start_link() ->
    gen_server:start_link(?MODULE, [], []).

stop(D) ->
    gen_server:call(D, stop).

preauth(D, Args = #{}) ->
    gen_server:call(D, {preauth, Args}).

auth(D, Args = #{}) ->
    gen_server:call(D, {auth, Args}).

auth_status(D, TxId) ->
    gen_server:call(D, {auth_status, TxId}).

-record(state, {gun, host, ikey, skey}).

init(_) ->
    DuoConfig = application:get_env(rdpproxy, duo, []),
    IKey = proplists:get_value(integration_key, DuoConfig),
    SKey = proplists:get_value(secret_key, DuoConfig),
    ApiHost = proplists:get_value(api_host, DuoConfig),
    {ok, Gun} = gun:open(ApiHost, 443),
    {ok, #state{gun = Gun, host = ApiHost, ikey = IKey, skey = SKey}}.

terminate(_Reason, _S = #state{gun = Gun}) ->
    gun:close(Gun),
    ok.

handle_info(Info, S = #state{}) ->
    {noreply, S}.

to_hex(Bin) ->
    << <<Y>> ||<<X:4>> <= Bin, Y <- integer_to_list(X,16)>>.

do_signed_req(Method, Path, Params, #state{gun = Gun, host = ApiHost, ikey = IKey, skey = SKey}) ->
    Date = http_signature_date:rfc7231(),
    MethodBin = string:uppercase(atom_to_binary(Method, utf8)),
    Qs = uri_string:compose_query(maps:to_list(Params)),
    SigningString = [
        Date, <<"\n">>,
        MethodBin, <<"\n">>,
        ApiHost, <<"\n">>,
        Path, <<"\n">>,
        Qs
    ],
    Mac = crypto:hmac(sha, SKey, SigningString),
    Authz = [<<"Basic ">>, base64:encode(iolist_to_binary([IKey, $:, to_hex(Mac)]))],
    Uri = case Method of
        get -> iolist_to_binary([Path, $?, Qs]);
        _ -> Path
    end,
    Body = case Method of
        get -> <<>>;
        _ -> iolist_to_binary(Qs)
    end,
    Hdrs0 = [
        {<<"date">>, Date},
        {<<"authorization">>, Authz}
    ],
    Hdrs1 = case Method of
        get -> Hdrs0;
        _ -> [{<<"content-type">>, <<"application/x-www-form-urlencoded">>} | Hdrs0]
    end,
    Req = gun:request(Gun, MethodBin, Uri, Hdrs1, Body),
    case gun:await(Gun, Req, 1000) of
        {response, fin, Status, Headers} ->
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

handle_call({preauth, Args}, _From, S = #state{}) ->
    case do_signed_req(post, <<"/auth/v2/preauth">>, Args, S) of
        {ok, 200, #{<<"response">> := Resp}} -> {reply, {ok, Resp}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call({auth, Args}, _From, S = #state{}) ->
    case do_signed_req(post, <<"/auth/v2/auth">>, Args, S) of
        {ok, 200, #{<<"response">> := Resp}} -> {reply, {ok, Resp}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call({auth_status, TxId}, _From, S = #state{}) ->
    Args = #{<<"txid">> => TxId},
    case do_signed_req(get, <<"/auth/v2/auth_status">>, Args, S) of
        {ok, 200, #{<<"response">> := Resp}} -> {reply, {ok, Resp}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call(check, _From, S = #state{}) ->
    case do_signed_req(get, <<"/auth/v2/check">>, #{}, S) of
        {ok, 200, #{<<"stat">> := <<"OK">>}} -> {reply, ok, S};
        {ok, Code, Info} -> {reply, {error, Info}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call(stop, _From, S = #state{}) ->
    {stop, normal, ok, S}.
