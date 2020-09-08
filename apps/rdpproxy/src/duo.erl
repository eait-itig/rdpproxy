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
-export([init/1, terminate/2, handle_call/3, handle_info/2, handle_cast/2]).

-export([preauth/2, auth/2, auth_status/2]).

-export([register_metrics/0]).

register_metrics() ->
    prometheus_histogram:new([
        {name, duo_request_duration_milliseconds},
        {buckets, [20, 50, 100, 500, 1000, 5000]},
        {labels, [method, path, status]},
        {duration_unit, false},
        {help, "Time spent waiting for Duo requests"} ]),
    prometheus_counter:new([
        {name, duo_request_errors_total},
        {labels, [method, path]},
        {help, "Errors from duo API"}]),
    prometheus_counter:new([
        {name, duo_preauth_results_per_user_total},
        {labels, [result, user]},
        {help, "The result field from Duo preauth replies"}]),
    prometheus_counter:new([
        {name, duo_auth_methods_per_user_total},
        {labels, [method, user]},
        {help, "Duo auth methods attempted"}]),
    prometheus_counter:new([
        {name, duo_preauth_results_total},
        {labels, [result]},
        {help, "The result field from Duo preauth replies"}]),
    prometheus_counter:new([
        {name, duo_auth_methods_total},
        {labels, [method]},
        {help, "Duo auth methods attempted"}]),
    ok.

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

-record(?MODULE, {gun, host, ikey, skey}).

init(_) ->
    DuoConfig = application:get_env(rdpproxy, duo, []),
    IKey = proplists:get_value(integration_key, DuoConfig),
    SKey = proplists:get_value(secret_key, DuoConfig),
    ApiHost = proplists:get_value(api_host, DuoConfig),
    {ok, Gun} = gun:open(ApiHost, 443),
    {ok, #?MODULE{gun = Gun, host = ApiHost, ikey = IKey, skey = SKey}}.

terminate(_Reason, _S = #?MODULE{gun = Gun}) ->
    gun:close(Gun),
    ok.

handle_info(_Info, S = #?MODULE{}) ->
    {noreply, S}.

handle_cast(_Msg, S = #?MODULE{}) ->
    {noreply, S}.

to_hex(Bin) ->
    << <<Y>> ||<<X:4>> <= Bin, Y <- integer_to_list(X,16)>>.

do_signed_req(Method, Path, Params, #?MODULE{gun = Gun, host = ApiHost, ikey = IKey, skey = SKey}) ->
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
    T0 = erlang:system_time(microsecond),
    Req = gun:request(Gun, MethodBin, Uri, Hdrs1, Body),
    case gun:await(Gun, Req, 1000) of
        {response, fin, Status, _Headers} ->
            T1 = erlang:system_time(microsecond),
            Delta = (T1 - T0) / 1000,
            prometheus_histogram:observe(duo_request_duration_milliseconds,
                [Method, Path, Status], round(Delta)),
            if
                (Status >= 500) ->
                    prometheus_counter:inc(duo_request_errors, [Method, Path]);
                true -> ok
            end,
            {ok, Status};
        {response, nofin, Status, Headers} ->
            RHdrs = maps:from_list(Headers),
            {ok, Body0} = gun:await_body(Gun, Req),
            T1 = erlang:system_time(microsecond),
            Delta = (T1 - T0) / 1000,
            prometheus_histogram:observe(duo_request_duration_milliseconds,
                [Method, Path, Status], round(Delta)),
            if
                (Status >= 500) ->
                    prometheus_counter:inc(duo_request_errors, [Method, Path]);
                true -> ok
            end,
            Body1 = case RHdrs of
                #{<<"content-type">> := <<"application/json">>} ->
                    jsx:decode(Body0, [return_maps]);
                _ -> Body0
            end,
            {ok, Status, Body1};
        Else ->
            prometheus_counter:inc(duo_request_errors, [Method, Path]),
            Else
    end.

handle_call({preauth, Args}, _From, S = #?MODULE{}) ->
    #{<<"username">> := U} = Args,
    case do_signed_req(post, <<"/auth/v2/preauth">>, Args, S) of
        {ok, 200, #{<<"response">> := Resp}} ->
            case Resp of
                #{<<"result">> := Res} ->
                    prometheus_counter:inc(duo_preauth_results_per_user_total,
                        [Res, U]),
                    prometheus_counter:inc(duo_preauth_results_total, [Res]);
                _ -> ok
            end,
            {reply, {ok, Resp}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call({auth, Args}, _From, S = #?MODULE{}) ->
    case Args of
        #{<<"username">> := U, <<"factor">> := F} ->
            prometheus_counter:inc(duo_auth_methods_per_user_total, [F, U]),
            prometheus_counter:inc(duo_auth_methods_total, [F]);
        _ -> ok
    end,
    case do_signed_req(post, <<"/auth/v2/auth">>, Args, S) of
        {ok, 200, #{<<"response">> := Resp}} -> {reply, {ok, Resp}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call({auth_status, TxId}, _From, S = #?MODULE{}) ->
    Args = #{<<"txid">> => TxId},
    case do_signed_req(get, <<"/auth/v2/auth_status">>, Args, S) of
        {ok, 200, #{<<"response">> := Resp}} -> {reply, {ok, Resp}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call(check, _From, S = #?MODULE{}) ->
    case do_signed_req(get, <<"/auth/v2/check">>, #{}, S) of
        {ok, 200, #{<<"stat">> := <<"OK">>}} -> {reply, ok, S};
        {ok, _Code, Info} -> {reply, {error, Info}, S};
        Else -> {reply, {error, Else}, S}
    end;

handle_call(stop, _From, S = #?MODULE{}) ->
    {stop, normal, ok, S}.
