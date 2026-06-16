%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2026 Lexi Wilson <lexi@uq.edu.au>
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

-module(okta).
-behaviour(gen_server).

-export([start_link/0, stop/1]).
-export([init/1, terminate/2, handle_call/3, handle_info/2, handle_cast/2]).
-export([
    remediations/1,
    rinfo/2,
    ainfo/1,
    begin_auth/1,
    begin_auth/2,
    proceed/2,
    proceed/3,
    map_remprops/2,
    map_remprops/3,
    mapfold_remprops/3,
    mapfold_remprops/4]).

-export([register_metrics/0]).

-include_lib("jose/include/jose.hrl").

register_metrics() ->
    prometheus_histogram:new([
        {name, okta_request_duration_milliseconds},
        {buckets, [20, 50, 100, 500, 1000, 5000]},
        {labels, []},
        {duration_unit, false},
        {help, "Time spent waiting for Okta requests"} ]),
    prometheus_counter:new([
        {name, okta_request_errors_total},
        {labels, []},
        {help, "Errors from Okta API"}]),
    ok.

start_link() ->
    gen_server:start_link(?MODULE, [], []).

stop(D) ->
    gen_server:call(D, stop).

-spec remediations(pid()) -> {ok, [remtype()]}.
remediations(P) ->
    gen_server:call(P, remediations).

-spec rinfo(pid(), remtype()) -> {ok, reminfo()} | {error, not_found} | {error, term()}.
rinfo(P, Type) when is_atom(Type) ->
    gen_server:call(P, {remediation_info, Type}).

-type accumulator() :: any().
-type path() :: [atom()].

-type propinfo_flat() :: simple_prop() | choice_prop_simple() | choice_prop_object().

-type map_remprops_value() :: simple_value() | choice_label().
-type map_remprops_fun() :: fun((path(), propinfo_flat()) -> map_remprops_value()).
-type map_remprops_option() :: simple_only | required_only.
-type map_remprops_options() :: [map_remprops_option()].

-type mapfold_remprops_fun() :: fun((path(), propinfo_flat(), accumulator()) -> {map_remprops_value(), accumulator()}).

-spec mapfold_remprops(mapfold_remprops_fun(), accumulator(), remprops()) -> {remarg_map(), accumulator()}.
mapfold_remprops(Fun, Acc, Props) ->
    mapfold_remprops([], Fun, Acc, Props, []).

-spec mapfold_remprops(mapfold_remprops_fun(), accumulator(), remprops(), map_remprops_options()) -> {remarg_map(), accumulator()}.
mapfold_remprops(Fun, Acc, Props, Options) ->
    mapfold_remprops([], Fun, Acc, Props, Options).

mapfold_remprops(Path, Fun, UAcc0, Props, Opts) ->
    SimpleOnly = lists:member(simple_only, Opts),
    RequiredOnly = lists:member(required_only, Opts),
    maps:fold(fun
        (K, {simple, #{required := false}}, {Acc, UAcc1}) when RequiredOnly ->
            {Acc, UAcc1};
        (K, {simple, #{required := true, default := V}}, {Acc, UAcc1}) when RequiredOnly ->
            {Acc#{K => V}, UAcc1};
        (K, P = {simple, _}, {Acc, UAcc1}) ->
            {V, UAcc2} = Fun([K | Path], P, UAcc1),
            {Acc#{K => V}, UAcc2};
        (K, {object, #{properties := InnerProps}}, {Acc, UAcc1}) ->
            {InnerObj, UAcc2} = mapfold_remprops([K | Path], Fun, UAcc1, InnerProps, Opts),
            {Acc#{K => InnerObj}, UAcc2};
        (K, {choice, _, Choices}, Acc) when SimpleOnly ->
            error({choice_required, [K | Path]});
        (K, P = {choice, _, Choices}, {Acc, UAcc1}) ->
            {Label, UAcc2} = Fun([K | Path], P, UAcc1),
            case [X || X = #{label := L} <- Choices, L =:= Label] of
                [#{value := _V}] ->
                    {Acc#{K => Label}, UAcc2};
                [#{properties := InnerProps}] ->
                    {InnerObj, UAcc3} = mapfold_remprops([K | Path], Fun, UAcc2, InnerProps, Opts),
                    {Acc#{K => {Label, InnerObj}}, UAcc3};
                _ ->
                    error({invalid_choice, [K | Path], Label})
            end
    end, {#{}, UAcc0}, Props).

-spec map_remprops(map_remprops_fun(), remprops()) -> remarg_map().
map_remprops(Fun, Props) ->
    map_remprops([], Fun, Props, []).

-spec map_remprops(map_remprops_fun(), remprops(), map_remprops_options()) -> remarg_map().
map_remprops(Fun, Props, Options) ->
    map_remprops([], Fun, Props, Options).

map_remprops(Path, Fun, Props, Opts) ->
    SimpleOnly = lists:member(simple_only, Opts),
    RequiredOnly = lists:member(required_only, Opts),
    maps:fold(fun
        (K, {simple, #{required := false}}, Acc) when RequiredOnly ->
            Acc;
        (K, {simple, #{required := true, default := V}}, Acc) when RequiredOnly ->
            Acc#{K => V};
        (K, P = {simple, _}, Acc) ->
            Acc#{K => Fun([K | Path], P)};
        (K, {object, #{properties := InnerProps}}, Acc) ->
            InnerObj = map_remprops([K | Path], Fun, InnerProps, Opts),
            Acc#{K => InnerObj};
        (K, {choice, _, Choices}, Acc) when SimpleOnly ->
            error({choice_required, [K | Path]});
        (K, P = {choice, _, Choices}, Acc) ->
            Label = Fun([K | Path], P),
            case [X || X = #{label := L} <- Choices, L =:= Label] of
                [#{value := _V}] ->
                    Acc#{K => Label};
                [#{properties := InnerProps}] ->
                    InnerObj = map_remprops([K | Path], Fun, InnerProps, Opts),
                    Acc#{K => {Label, InnerObj}};
                _ ->
                    error({invalid_choice, [K | Path], Label})
            end
    end, #{}, Props).

-spec ainfo(pid()) -> {ok, authinfo()} | {error, term()}.
ainfo(P) ->
    gen_server:call(P, authenticator_info).

-spec msgs(pid()) -> {ok, [msg()]} | {error, term()}.
msgs(P) ->
    gen_server:call(P, get_messages).

-spec begin_auth(pid()) -> {ok, next_steps, #{remtype() => reminfo()}} | {error, term()}.
begin_auth(P) ->
    gen_server:call(P, begin_auth).

-spec begin_auth(pid(), client_metadata()) ->
    {ok, next_steps, #{remtype() => reminfo()}} |
    {warning, [msg()], next_steps, #{remtype() => reminfo()}} |
    {error, [msg()], next_steps, #{remtype() => reminfo()}} |
    {error, term()}.
begin_auth(P, Meta) when is_map(Meta) ->
    gen_server:call(P, {begin_auth, Meta}).

-spec proceed(pid(), remtype()) ->
    {ok, next_steps, #{remtype() => reminfo()}} |
    {ok, finished, tokens()} |
    {warning, [msg()], next_steps, #{remtype() => reminfo()}} |
    {error, [msg()], next_steps, #{remtype() => reminfo()}} |
    {error, term()}.
proceed(P, Rem) when is_atom(Rem) ->
    gen_server:call(P, Rem).

-spec proceed(pid(), remtype(), remarg_map()) -> {ok, next_steps, #{remtype() => reminfo()}} | {ok, finished, tokens()} | {error, term()}.
proceed(P, Rem, Args) when is_atom(Rem) and is_map(Args) ->
    gen_server:call(P, {Rem, Args}).

-type msg() :: {error | info, binary()}.

-type client_metadata() :: #{login_hint => binary(), os_type => atom(),
    os_subtype => atom(), os_build => integer(),
    rdp_version => {integer(), integer()}}.

-type simple_value() :: binary().
-type remarg_value() :: simple_value() | remarg_map() | choice_label() |
    {choice_label(), simple_value()} | {choice_label(), remarg_map()}.
-type remarg_map() :: #{atom() => remarg_value()}.

-type remtype() :: identify | redirect_idp | challenge_webauthn |
    challenge_poll | select_authenticator | challenge_authenticator |
    device_challenge_poll | cancel_polling | cancel.

-type password_info() :: #{}.
-type webauthn_info() :: #{device_name => binary(), aaguid => binary(),
    challenge => binary(), cred_id => binary(), app_id => binary(),
    uv_required => boolean()}.
-type loopback_device_info() :: #{challenge => binary(), domain => binary(),
    ports => [integer()], timeout => integer()}.
-type custom_uri_device_info() :: #{uri => binary()}.
-type app_info() :: #{device_name => binary(), push_code => binary()}.
-type secq_info() :: #{question => atom() | {custom, binary()}, answer => binary()}.
-type email_info() :: #{email => binary()}.
-type phone_info() :: #{number => binary()}.

-type auth_common_info() :: #{methods => [atom()], remediations => [remtype()],
    name => binary()}.

-type authinfo() :: {password, auth_common_info(), password_info()} |
    {loopback_device, auth_common_info(), loopback_device_info()} |
    {custom_uri_device, auth_common_info(), custom_uri_device_info()} |
    {app, auth_common_info(), app_info()} |
    {security_question, auth_common_info(), secq_info()} |
    {email, auth_common_info(), email_info()} |
    {phone, auth_common_info(), phone_info()} |
    {webauthn, auth_common_info(), webauthn_info()}.

-type reminfo() :: #{properties => remprops(), authenticator => authinfo(),
    refresh => integer(), name => binary()}.

-type remprops() :: #{atom() => propinfo()}.

-type propinfo() :: simple_prop() | object_prop() |
    choice_prop_object() | choice_prop_simple().

-type simple_prop() :: {simple, #{required => boolean(), visible => boolean(),
    default => binary(), label => binary()}}.
-type object_prop() :: {object, #{required => boolean(),
    properties => remprops()}}.
-type choice_prop_object() :: {choice, #{required => boolean()},
    [choice_object()]}.
-type choice_prop_simple() :: {choice, #{required => boolean()},
    [choice_simple()]}.
-type choice_label() :: binary().
-type choice_simple() :: #{label => choice_label(), value => binary(),
    authenticator => authinfo()}.
-type choice_object() :: #{label => choice_label(), authenticator => authinfo(),
    properties => remprops()}.

-type tokens() :: #{claims => map(), access_token => binary(),
    id_token => binary(), scopes => [atom()], type => bearer}.

-record(authenticator, {
    id :: auth_id(),
    name :: binary(),
    type :: binary(),
    methods :: [atom()],
    remediations = #{} :: #{remtype() => remediation()},
    enrollments = [] :: [enroll_id()]
    }).

-record(webauthn_enroll, {
    device_name :: binary(),
    cred_id :: undefined | binary(),
    aaguid :: undefined | binary(),
    challenge :: undefined | binary(),
    appid :: undefined | binary(),
    uvreq :: undefined | boolean()
    }).

-record(password_enroll, {
    }).

-record(app_enroll, {
    device_name :: binary(),
    push_code :: undefined | binary()
    }).

-record(device_loopback_enroll, {
    challenge :: binary(),
    domain :: binary(),
    ports :: [integer()],
    timeout :: integer()
    }).

-record(device_uri_enroll, {
    href :: binary()
    }).

-record(secq_enroll, {
    question :: atom() | {custom, binary()},
    answer :: undefined | binary()
    }).

-record(email_enroll, {
    email :: binary()
    }).

-record(phone_enroll, {
    number :: binary()
    }).

-record(simple_field, {
    label :: undefined | binary(),
    required :: boolean(),
    mutable :: boolean(),
    visible :: boolean(),
    default :: undefined | binary()
    }).

-record(object_field, {
    required :: boolean(),
    fields :: #{binary() => field()}
    }).

-record(options_field, {
    required :: boolean(),
    options :: #{binary() => option()}
    }).

-record(object_option, {
    authenticator :: undefined | auth_id() | {auth_id(), enroll_id()},
    fields :: #{binary() => field()}
    }).

-record(string_option, {
    authenticator :: undefined | auth_id() | {auth_id(), enroll_id()},
    value :: binary()
    }).

-type auth_id() :: binary().
-type auth_key() :: binary().
-type enroll_id() :: binary().

-record(remediation, {
    name :: binary(),
    method :: get | post,
    host :: binary(),
    path :: binary(),
    refresh :: undefined | integer(),
    authenticator :: undefined | auth_id() | {auth_id(), enroll_id()},
    fields = #{} :: #{binary() | atom() => field()}
    }).

-record(message, {
    class :: error | info | atom(),
    i18n_key :: undefined | binary(),
    message :: binary()
    }).

-type authenticator() :: #authenticator{}.
-type enrollment() :: #webauthn_enroll{} | #password_enroll{} | #app_enroll{} |
    #device_loopback_enroll{} | #device_uri_enroll{} | #email_enroll{} |
    #phone_enroll{} | #secq_enroll{}.
-type field() :: #simple_field{} | #object_field{} | #options_field{}.
-type remediation() :: #remediation{}.
-type option() :: #object_option{} | #string_option{}.

-record(?MODULE, {
    gunopts :: map(),
    gunmap = #{} :: #{binary() => pid()},
    host :: binary(),
    cid :: binary(),
    redir :: binary(),
    key :: map(),
    addhdrs = #{} :: #{binary() => binary()},
    verifier :: undefined | binary(),
    ihdl :: undefined | binary(),
    sthdl :: undefined | binary(),
    app :: undefined | binary(),
    rems = #{} :: #{atom() => remediation()},
    authns = #{} :: #{auth_id() => authenticator()},
    enrolls = #{} :: #{enroll_id() => {auth_key(), authenticator(), enrollment()}},
    eauthn = #{} :: #{enroll_id() => auth_id()},
    curauth :: undefined | enroll_id(),
    idpkeys = #{} :: #{binary() => map()},
    msgs = [] :: [#message{}]
    }).

init(_) ->
    OktaConfig = application:get_env(rdpproxy, okta, []),
    ApiHost = proplists:get_value(host, OktaConfig),
    ClientID = proplists:get_value(client_id, OktaConfig),
    RedirURI = proplists:get_value(redirect_uri, OktaConfig),
    Key = proplists:get_value(key, OktaConfig),
    Timeout = 10000,
    TOpts0 = [
        {verify, verify_peer},
        {customize_hostname_check, [{match_fun,
            public_key:pkix_verify_hostname_match_fun(https)}]}
        ],
    TOpts1 = case erlang:function_exported(public_key, cacerts_get, 0) of
        true ->
            TOpts0 ++ [{cacerts, public_key:cacerts_get()}];
        false ->
            TOpts0
    end,
    Opts = #{
        protocols => [http],
        connect_timeout => Timeout,
        tls_handshake_timeout => Timeout,
        domain_lookup_timeout => Timeout,
        retry => 1,
        tcp_opts => [
            {send_timeout, Timeout},
            {send_timeout_close, true},
            {keepalive, true}
        ],
        transport => tls,
        tls_opts => TOpts1,
        supervise => false
        },
    S0 = #?MODULE{gunopts = Opts, host = ApiHost, cid = ClientID,
                  redir = RedirURI, key = Key},
    {_ApiGun, S1} = open_gun(ApiHost, S0),
    {ok, S1}.

open_gun(Host, S0 = #?MODULE{gunmap = GM0, gunopts = Opts}) ->
    case GM0 of
        #{Host := Gun} ->
            {Gun, S0};
        _ ->
            {ok, Gun} = gun:open(unicode:characters_to_list(Host, utf8), 443, Opts),
            {Gun, S0#?MODULE{gunmap = GM0#{Host => Gun}}}
    end.

terminate(_Reason, _S = #?MODULE{gunmap = GunMap}) ->
    maps:foreach(fun (_Host, Gun) -> gun:close(Gun) end, GunMap),
    ok.

handle_info(_Info, S = #?MODULE{}) ->
    {noreply, S}.

handle_cast(_Msg, S = #?MODULE{}) ->
    {noreply, S}.

field_name_to_atom(B0) ->
    B1 = binary:replace(B0, [<<"-">>], <<"_">>, [global]),
    B2 = binary:replace(B1, [<<X>> || X <- lists:seq($A, $Z)],
        fun (X) -> <<"_", (string:lowercase(X))/binary>> end, [global]),
    binary_to_atom(B2, utf8).

compose_field_payload(Args, FieldMap) ->
    maps:fold(fun
        (Key, #simple_field{required = Req, default = Def}, Acc) ->
            V = maps:get(Key, Args,
                    maps:get(field_name_to_atom(Key), Args, undefined)),
            case {Req, Def, V} of
                {true, undefined, undefined} ->
                    error({required_field, Key});
                {false, undefined, undefined} ->
                    Acc;
                {_, _Def, undefined} ->
                    Acc#{Key => Def};
                {_, _, _V} ->
                    Acc#{Key => V}
            end;

        (Key, #object_field{fields = SubFieldMap}, Acc) ->
            SubArgs = maps:get(Key, Args,
                    maps:get(field_name_to_atom(Key), Args, #{})),
            Acc#{Key => compose_field_payload(SubArgs, SubFieldMap)};

        (Key, #options_field{required = Req, options = Opts}, Acc) ->
            V = maps:get(Key, Args,
                    maps:get(field_name_to_atom(Key), Args, undefined)),
            case {Req, V} of
                {true, undefined} ->
                    error({required_field, Key});
                {false, undefined} ->
                    Acc;
                _ ->
                    {Opt, Content} = case V of
                        {OptKey, Content0} ->
                            case Opts of
                                #{OptKey := Opt0} -> {Opt0, Content0};
                                _ -> error({invalid_option, Key, OptKey})
                            end;
                        OptKey ->
                            case Opts of
                                #{OptKey := Opt0} -> {Opt0, undefined};
                                _ -> error({invalid_option, Key, OptKey})
                            end
                    end,
                    case Opt of
                        #string_option{value = OV} ->
                            Acc#{Key => OV};
                        #object_option{fields = OptFields} ->
                            ObjContent = case Content of
                                undefined -> #{};
                                _ -> Content
                            end,
                            Acc#{Key => compose_field_payload(ObjContent, OptFields)}
                    end
            end
    end, #{}, FieldMap).

compose_rem_payload(Args, #remediation{fields = FMap}, S0 = #?MODULE{}) ->
    case (catch compose_field_payload(Args, FMap)) of
        {'EXIT', Why} ->
            {error, {bad_payload, Why}, S0};
        Payload ->
            {ok, Payload}
    end.

get_json(Host, Path, S0 = #?MODULE{addhdrs = Hdrs0}) ->
    {Gun, S1} = open_gun(Host, S0),
    Req = gun:get(Gun, Path, Hdrs0#{
        <<"accept">> => <<"application/ion+json; okta-version=1.0.0">>
    }),
    req_json_reply(Gun, Req, S1).

post_json(Host, Path, Data, S0 = #?MODULE{addhdrs = Hdrs0}) ->
    {Gun, S1} = open_gun(Host, S0),
    Req = gun:post(Gun, Path, Hdrs0#{
        <<"content-type">> => <<"application/json">>,
        <<"accept">> => <<"application/ion+json; okta-version=1.0.0">>
    }, json:encode(Data)),
    req_json_reply(Gun, Req, S1).

post_formenc(Host, Path, Qs, S0 = #?MODULE{addhdrs = Hdrs0}) ->
    {Gun, S1} = open_gun(Host, S0),
    Req = gun:post(Gun, Path, Hdrs0#{
       <<"content-type">> => <<"application/x-www-form-urlencoded">>,
       <<"accept">> => <<"application/json">>
    }, cow_qs:qs(Qs)),
    req_json_reply(Gun, Req, S1).

req_json_reply(Gun, Req, S0 = #?MODULE{}) ->
    T0 = erlang:system_time(microsecond),
    case gun:await(Gun, Req) of
        {response, fin, Status, _Headers} ->
            T1 = erlang:system_time(microsecond),
            Delta = (T1 - T0) / 1000,
            prometheus_histogram:observe(okta_request_duration_milliseconds, round(Delta)),
            if
                (Status >= 500) ->
                    prometheus_counter:inc(okta_request_errors_total, []);
                true -> ok
            end,
            case Status of
                200 -> {ok, S0};
                _ -> {error, {http, Status}, S0}
            end;
        {response, nofin, Status, Headers} ->
            _RHdrs = maps:from_list(Headers),
            {ok, Body0} = gun:await_body(Gun, Req),
            T1 = erlang:system_time(microsecond),
            Delta = (T1 - T0) / 1000,
            prometheus_histogram:observe(okta_request_duration_milliseconds, round(Delta)),
            if
                (Status >= 500) ->
                    prometheus_counter:inc(okta_request_errors_total);
                true -> ok
            end,
            Body1 = json:decode(Body0),
            case Status of
                200 -> {ok, Body1, S0};
                _ -> {error, {http, Status, Body1}, S0}
            end;
        {error, Why} ->
            prometheus_counter:inc(okta_request_errors_total),
            {error, Why, S0}
    end.

method_to_atom(<<"POST">>) -> post;
method_to_atom(<<"GET">>) -> get.

fix_jsonpath_ref(X = <<"$", _/binary>>) -> X;
fix_jsonpath_ref(X) -> <<"$.", X/binary>>.

parse_object_option(O = #{<<"label">> := Lbl, <<"value">> := V}, D, Acc) ->
    AuthID = case O of
        #{<<"relatesTo">> := AuthPath} -> auth_ref_to_id(AuthPath, D);
        _ -> undefined
    end,
    #{<<"form">> := #{<<"value">> := Fields0}} = V,
    Fields1 = parse_fields(Fields0, D),
    Acc#{Lbl => #object_option{authenticator = AuthID, fields = Fields1}}.

parse_string_option(O = #{<<"label">> := Lbl, <<"value">> := V}, D, Acc) ->
    AuthID = case O of
        #{<<"relatesTo">> := AuthPath} -> auth_ref_to_id(AuthPath, D);
        _ -> undefined
    end,
    Opt = #string_option{authenticator = AuthID, value = V},
    Acc#{Lbl => Opt, V => Opt}.

parse_field(#{<<"type">> := <<"object">>, <<"options">> := Opts0}, D) ->
    Opts1 = lists:foldl(fun (Opt, Acc) ->
        parse_object_option(Opt, D, Acc)
    end, #{}, Opts0),
    #options_field{required = true, options = Opts1};
parse_field(F = #{<<"type">> := <<"string">>, <<"options">> := Opts0}, D) ->
    Req = maps:get(<<"required">>, F, false),
    Opts1 = lists:foldl(fun (Opt, Acc) ->
        parse_string_option(Opt, D, Acc)
    end, #{}, Opts0),
    #options_field{required = Req, options = Opts1};
parse_field(F = #{<<"type">> := <<"object">>, <<"form">> := Form}, D) ->
    #{<<"value">> := FormValue} = Form,
    Fields = parse_fields(FormValue, D),
    Req = maps:get(<<"required">>, F, false),
    #object_field{required = Req,
                  fields = Fields};
parse_field(F = #{}, _D) ->
    Lbl = maps:get(<<"label">>, F, undefined),
    Req = maps:get(<<"required">>, F, false),
    Vis = maps:get(<<"visible">>, F, true),
    Mut = maps:get(<<"mutable">>, F, true),
    Def = maps:get(<<"value">>, F, undefined),
    #simple_field{label = Lbl,
                  required = Req,
                  visible = Vis,
                  mutable = Mut,
                  default = Def}.

parse_href(Bin) ->
    #{host := Host, path := Path, scheme := <<"https">>} = uri_string:parse(Bin),
    {Host, Path}.

parse_methods([]) -> [];
parse_methods([#{<<"type">> := Bin} | Rest]) ->
    [binary_to_atom(Bin, utf8) | parse_methods(Rest)].

parse_enrollment(#{<<"type">> := <<"password">>}, _D) ->
    #password_enroll{};

parse_enrollment(E = #{<<"type">> := <<"email">>}, _D) ->
    #{<<"profile">> := #{<<"email">> := Email}} = E,
    #email_enroll{email = Email};

parse_enrollment(E = #{<<"type">> := <<"device">>,
                       <<"challengeMethod">> := <<"LOOPBACK">>}, _D) ->
    #{<<"challengeRequest">> := Chal,
      <<"domain">> := Domain,
      <<"ports">> := PortsBins,
      <<"probeTimeoutMillis">> := Timeout} = E,
    Ports = [binary_to_integer(X) || X <- PortsBins],
    #device_loopback_enroll{challenge = Chal, domain = Domain, ports = Ports,
                            timeout = Timeout};
parse_enrollment(E = #{<<"type">> := <<"device">>,
                       <<"challengeMethod">> := <<"CUSTOM_URI">>}, _D) ->
    #{<<"href">> := Href} = E,
    #device_uri_enroll{href = Href};

parse_enrollment(E = #{<<"type">> := <<"security_question">>}, _D) ->
    % TODO: is this in the contextualData or something?
    Q = case E of
        #{<<"question_key">> := <<"custom">>, <<"question">> := QQ} ->
            {custom, QQ};
        #{<<"question_key">> := Key} ->
            binary_to_atom(Key, utf8)
    end,
    Ans = maps:get(<<"answer">>, E, undefined),
    #secq_enroll{question = Q, answer = Ans};

parse_enrollment(E = #{<<"type">> := <<"app">>,
                       <<"contextualData">> := CD}, _D) ->
    #{<<"correctAnswer">> := PushCode} = CD,
    Profile = maps:get(<<"profile">>, E, #{}),
    DevName = maps:get(<<"deviceName">>, Profile, undefined),
    #app_enroll{device_name = DevName, push_code = PushCode};
parse_enrollment(E = #{<<"type">> := <<"app">>}, _D) ->
    Profile = maps:get(<<"profile">>, E, #{}),
    DevName = maps:get(<<"deviceName">>, Profile, undefined),
    #app_enroll{device_name = DevName};

parse_enrollment(E = #{<<"type">> := <<"phone">>}, _D) ->
    #{<<"profile">> := #{<<"phoneNumber">> := Num}} = E,
    #phone_enroll{number = Num};

parse_enrollment(E0 = #{<<"type">> := <<"security_key">>,
                        <<"contextualData">> := CD}, D) ->
    #{<<"challengeData">> := ChalData} = CD,
    E1 = maps:remove(<<"contextualData">>, E0),
    parse_enrollment(E1#{<<"challengeData">> => ChalData}, D);

parse_enrollment(E = #{<<"type">> := <<"security_key">>,
                       <<"challengeData">> := CD}, _D) ->
    #{<<"challenge">> := Challenge,
      <<"extensions">> := #{<<"appid">> := AppId}} = CD,
    UserVerif = (maps:get(<<"userVerification">>, CD, undefined) =:= <<"required">>),
    #{<<"displayName">> := DevName} = E,
    CredId = maps:get(<<"credentialId">>, E, undefined),
    Profile = maps:get(<<"profile">>, E, #{}),
    AAGuid = maps:get(<<"aaguid">>, Profile, undefined),
    #webauthn_enroll{device_name = DevName,
                     cred_id = CredId,
                     aaguid = AAGuid,
                     challenge = Challenge,
                     appid = AppId,
                     uvreq = UserVerif};
parse_enrollment(E = #{<<"type">> := <<"security_key">>}, _D) ->
    #{<<"displayName">> := DevName,
      <<"credentialId">> := CredId,
      <<"profile">> := #{<<"aaguid">> := AAGuid}} = E,
    #webauthn_enroll{device_name = DevName,
                     cred_id = CredId,
                     aaguid = AAGuid}.

add_or_merge_enroll(EID, Key, Authn, Enroll, S0 = #?MODULE{enrolls = E0}) ->
    E1 = case E0 of
        #{EID := {_Key0, Authn0, Enroll0}} ->
            E0#{EID => {Key, merge_records(Authn0, Authn),
                             merge_records(Enroll0, Enroll)}};
        _ ->
            E0#{EID => {Key, Authn, Enroll}}
    end,
    S0#?MODULE{enrolls = E1}.

add_enroll_and_auth(EID, Key,
                    Authn = #authenticator{id = AID, remediations = ARems},
                    Enroll, S0 = #?MODULE{}) ->
    #?MODULE{enrolls = E0, authns = A0, eauthn = EA0, rems = R0} = S0,
    E1 = E0#{EID => {Key, Authn, Enroll}},
    A1 = A0#{AID => Authn},
    EA1 = EA0#{EID => AID},
    R1 = maps:merge(R0, ARems),
    S0#?MODULE{enrolls = E1, authns = A1, eauthn = EA1, rems = R1}.

auth_or_enroll_to_id(#{<<"type">> := <<"object">>, <<"value">> := V}) ->
    auth_or_enroll_to_id(V);
auth_or_enroll_to_id(#{<<"id">> := ID, <<"key">> := _Key}) -> ID;
auth_or_enroll_to_id(#{<<"key">> := Key}) -> Key.

auth_ref_to_id(Ref, D) ->
    {[Raw], _} = ejsonpath:q(unicode:characters_to_list(
        fix_jsonpath_ref(Ref), utf8), D),
    auth_or_enroll_to_id(Raw).

parse_enrollments(D = #{<<"currentAuthenticatorEnrollment">> := Obj}, S0) ->
    #{<<"type">> := <<"object">>, <<"value">> := E} = Obj,
    #{<<"key">> := Key} = E,
    Authn0 = #authenticator{id = EID} = parse_authenticator(E, D),
    Authn1 = Authn0#authenticator{enrollments = [EID]},
    Enroll = parse_enrollment(E, D),
    S1 = add_or_merge_enroll(EID, Key, Authn1, Enroll, S0),
    S2 = S1#?MODULE{curauth = EID},
    parse_enrollments(maps:remove(<<"currentAuthenticatorEnrollment">>, D), S2);
parse_enrollments(D = #{<<"currentAuthenticator">> := Obj}, S0) ->
    #{<<"type">> := <<"object">>, <<"value">> := E} = Obj,
    #{<<"key">> := Key} = E,
    Authn = #authenticator{id = AID} = parse_authenticator(E, D),
    Enroll = parse_enrollment(E, D),
    S1 = add_or_merge_enroll(AID, Key, Authn, Enroll, S0),
    S2 = S1#?MODULE{curauth = AID},
    parse_enrollments(maps:remove(<<"currentAuthenticator">>, D), S2);
parse_enrollments(D = #{<<"webauthnAutofillUIChallenge">> := Obj},
                  S0 = #?MODULE{curauth = undefined}) ->
    #{<<"type">> := <<"object">>, <<"value">> := C0} = Obj,
    % auth-challenges don't have an explicit ID or key, we make a synthetic
    % one, and device-challenge-poll etc will go along with it later
    EID = <<"$.webauthnAutofillUIChallenge">>,
    AID = <<"$.webauthnAutofillUIChallenge.authenticator">>,
    Key = <<"$.webauthnAutofillUIChallenge.key">>,
    C1 = C0#{<<"id">> => EID,
             <<"key">> => Key,
             <<"type">> => <<"security_key">>,
             <<"methods">> => [#{<<"type">> => <<"webauthn">>}],
             <<"displayName">> => <<"WebAuthn Auto-fill">>},
    Authn0 = parse_authenticator(C1, D),
    Authn1 = Authn0#authenticator{enrollments = [EID], id = AID},
    Enroll = parse_enrollment(C1, D),
    S1 = add_enroll_and_auth(EID, Key, Authn1, Enroll, S0),
    parse_enrollments(maps:remove(<<"webauthnAutofillUIChallenge">>, D), S1);
parse_enrollments(D = #{<<"authenticatorChallenge">> := Obj},
                  S0 = #?MODULE{curauth = undefined}) ->
    #{<<"type">> := <<"object">>, <<"value">> := C0} = Obj,
    #{<<"challengeMethod">> := Method} = C0,
    Type = case Method of
        <<"LOOPBACK">> -> <<"device">>;
        <<"CUSTOM_URL">> -> <<"device">>
    end,
    % auth-challenges don't have an explicit ID or key, we make a synthetic
    % one, and device-challenge-poll etc will go along with it later
    EID = <<"$.authenticatorChallenge">>,
    AID = <<"$.authenticatorChallenge.authenticator">>,
    Key = <<"$.authenticatorChallenge.key">>,
    C1 = C0#{<<"id">> => EID,
             <<"key">> => Key,
             <<"type">> => Type,
             <<"methods">> => [#{<<"type">> => <<"poll">>}]},
    Authn0 = parse_authenticator(C1, D),
    Authn1 = Authn0#authenticator{enrollments = [EID], id = AID},
    Enroll = parse_enrollment(C1, D),
    S1 = add_enroll_and_auth(EID, Key, Authn1, Enroll, S0),
    parse_enrollments(maps:remove(<<"authenticatorChallenge">>, D), S1);
parse_enrollments(D = #{<<"authenticatorChallenge">> := Obj},
                  S0 = #?MODULE{curauth = Id, enrolls = E0}) ->
    #{<<"type">> := <<"object">>, <<"value">> := C0} = Obj,
    #{Id := {Key, A = #authenticator{type = Type}, _}} = E0,
    C1 = C0#{<<"id">> => Id, <<"key">> => Key, <<"type">> => Type},
    Enroll = parse_enrollment(C1, D),
    S1 = add_or_merge_enroll(Id, Key, A, Enroll, S0),
    parse_enrollments(maps:remove(<<"authenticatorChallenge">>, D), S1);
parse_enrollments(D = #{<<"authenticatorEnrollments">> := Obj}, S0) ->
    #{<<"type">> := <<"array">>, <<"value">> := List} = Obj,
    S1 = lists:foldl(fun (E, Acc) ->
        #{<<"key">> := Key} = E,
        ID = maps:get(<<"id">>, E, Key),
        Authn0 = parse_authenticator(E, D),
        Authn1 = Authn0#authenticator{enrollments = [ID]},
        Enroll = parse_enrollment(E, D),
        add_or_merge_enroll(ID, Key, Authn1, Enroll, Acc)
    end, S0, List),
    parse_enrollments(maps:remove(<<"authenticatorEnrollments">>, D), S1);
parse_enrollments(_D, S0) -> S0.

parse_authenticators(D = #{<<"authenticators">> := #{
                            <<"type">> := <<"array">>,
                            <<"value">> := List}}, S0) ->
    S1 = lists:foldl(fun (A, Acc) ->
        #?MODULE{rems = R0, authns = A0, eauthn = EA0, enrolls = E0,
                 curauth = OldCurEID} = Acc,
        #{<<"id">> := AID, <<"key">> := Key} = A,

        Authn0 = parse_authenticator(A, D),
        Authn1 = case A0 of
            #{AID := OldAuthn} -> merge_records(Authn0, OldAuthn);
            _ -> Authn0
        end,

        % This is the special AID=EID entry made by currentAuthenticator etc.
        % We want to combine its info with the other enrollments. The properties
        % on its #authenticator should also overrule the ones from the
        % "authenticators" array.
        {Authn2, E1} = case E0 of
            #{AID := {_CKey, CAuthn, CE}} ->
                {merge_records(Authn1, CAuthn), maps:fold(fun
                    (EID, _, CAcc) when EID =:= AID ->
                        CAcc;
                    (EID, {EKey, EAuthn, E}, CAcc) when EKey =:= Key ->
                        V1 = {EKey, EAuthn, merge_records(E, CE)},
                        CAcc#{EID => V1};
                    (EID, V, CAcc) ->
                        CAcc#{EID => V}
                end, #{}, E0)};
            _ ->
                {Authn1, E0}
        end,

        % Now merge in any additional info on the enrollments' #authenticators.
        % Don't overwrite anything we have so far.
        Authn3 = maps:fold(fun
            (EID, {EKey, EAuthn, _E}, EAcc) when (EKey =:= Key) and not (EID =:= AID) ->
                merge_records(EAuthn, EAcc);
            (_, _, EAcc) -> EAcc
        end, Authn2, E1),

        #authenticator{remediations = ARems, enrollments = EIDs} = Authn3,
        NewCurEID = case OldCurEID of
            AID -> [FirstEID | _] = EIDs, FirstEID;
            _ -> OldCurEID
        end,
        A1 = A0#{AID => Authn3},
        EA1 = lists:foldl(fun (EnrollId, EAAcc) ->
            EAAcc#{EnrollId => AID}
        end, EA0, EIDs),
        % Merge remediations from this authenticator into the root
        R1 = maps:merge(R0, ARems),
        Acc0 = Acc#?MODULE{authns = A1, rems = R1, eauthn = EA1, enrolls = E1,
                    curauth = NewCurEID},
        Acc0
    end, S0, List),
    parse_authenticators(maps:remove(<<"authenticators">>, D), S1);

parse_authenticators(_D, S0) -> S0.

parse_authn_rems([], _A, _D) -> #{};
parse_authn_rems([Next | Rest], A = #{<<"key">> := AKey}, D) ->
    AID = maps:get(<<"id">>, A, AKey),
    case A of
        #{Next := R} ->
            M0 = parse_remediation(R, D),
            M1 = maps:map(fun
                (_K, R0 = #remediation{authenticator = undefined}) ->
                    R0#remediation{authenticator = AID};
                (_K, R0) ->
                    R0
            end, M0),
            maps:merge(M1, parse_authn_rems(Rest, A, D));
        _ ->
            parse_authn_rems(Rest, A, D)
    end.

parse_authenticator(A = #{<<"key">> := Key}, D) ->
    ID = maps:get(<<"id">>, A, Key),
    Name = maps:get(<<"displayName">>, A, Key),
    Methods = parse_methods(maps:get(<<"methods">>, A, [])),
    Rems = parse_authn_rems([<<"recover">>, <<"cancel">>, <<"resend">>,
        <<"poll">>, <<"send">>], A, D),
    Type = maps:get(<<"type">>, A, undefined),
    #authenticator{id = ID, type = Type, name = Name, methods = Methods,
                   remediations = Rems}.

parse_fields([], _D) -> #{};
parse_fields([F = #{<<"name">> := Name} | Rest], D) ->
    (parse_fields(Rest, D))#{Name => parse_field(F, D)}.

worst_msg_verb([#message{class = error}]) -> error;
worst_msg_verb([#message{}]) -> warning;
worst_msg_verb([#message{class = error} | _Rest]) -> error;
worst_msg_verb([#message{} | Rest]) -> worst_msg_verb(Rest).

msg_to_tuple(#message{class = Class, message = Text}) ->
    {Class, Text}.

err2reply({reply, Msg, State}) -> {reply, Msg, State};
err2reply({error, {http, Status, Body}, S0}) ->
    case (catch parse_response(Body, S0)) of
        {'EXIT', _} ->
            {reply, {error, {http, Status, Body}}, S0};
        {ok, {ok, next_steps, Rems}, S1} ->
            #?MODULE{msgs = Msgs} = S1,
            MsgMaps = [msg_to_tuple(M) || M <- Msgs],
            Verb = worst_msg_verb(Msgs),
            {reply, {Verb, MsgMaps, next_steps, Rems}, S1}
    end;
err2reply({error, Why, State}) -> {reply, {error, Why}, State}.

parse_response(D = #{<<"app">> := #{<<"type">> := <<"object">>,
                                    <<"value">> := AppInfo}}, S0 = #?MODULE{}) ->
    #{<<"label">> := AppLabel} = AppInfo,
    parse_response(maps:remove(<<"app">>, D),
                   S0#?MODULE{msgs = [], app = AppLabel});

parse_response(D = #{<<"messages">> := #{<<"type">> := <<"array">>,
                                         <<"value">> := Msgs}}, S0 = #?MODULE{}) ->
    MsgRecs = lists:map(fun (Msg) ->
        #{<<"class">> := ClsBin, <<"message">> := Text} = Msg,
        Class = binary_to_atom(string:lowercase(ClsBin), utf8),
        I18n = maps:get(<<"i18n">>, Msg, #{}),
        Key = maps:get(<<"key">>, I18n, undefined),
        #message{class = Class, i18n_key = Key, message = Text}
    end, Msgs),
    parse_response(maps:remove(<<"messages">>, D),
                   S0#?MODULE{msgs = MsgRecs});

parse_response(D = #{<<"stateHandle">> := StHdl,
                     <<"remediation">> := NewRem,
                     <<"cancel">> := CancelRem}, S0 = #?MODULE{}) ->
    S1 = S0#?MODULE{rems = #{}, authns = #{}, enrolls = #{}, eauthn = #{},
                    curauth = undefined},

    S2 = parse_enrollments(D, S1),
    S3 = parse_authenticators(D, S2),

    #?MODULE{rems = R0} = S3,
    R1 = maps:merge(R0, parse_remediation(NewRem, D)),
    R2 = maps:merge(R1, parse_remediation(CancelRem, D)),

    S4 = S3#?MODULE{sthdl = StHdl, rems = R2},

    RInfo = maps:map(fun (_K, V) -> remediation_to_map(V, S4) end, R2),

    {ok, {ok, next_steps, RInfo}, S4};

parse_response(D = #{<<"successWithInteractionCode">> := NewRem},
               S0 = #?MODULE{}) ->
    maybe
        #{issue := IssueRem} = parse_remediation(NewRem, D),
        {ok, S1} ?= do_get_idp_keys(IssueRem, S0),
        {ok, TokInfo0, S2} ?= do_issue_token(IssueRem, S1),
        {ok, Claims} ?= do_verify_token(TokInfo0, S2),
        TokInfo1 = tokinfo_to_map(TokInfo0, Claims),
        {ok, {ok, finished, TokInfo1}, S2}
    end.

unalias_remediation(<<"challenge-webauthn-autofillui-authenticator">>) -> challenge_webauthn_autofill;
unalias_remediation(<<"select-authenticator-authenticate">>) -> select_authenticator;
unalias_remediation(X) -> field_name_to_atom(X).

default_refresh_for_rem(N) when is_binary(N) and (byte_size(N) > 5) ->
    case binary:part(N, {byte_size(N), -5}) of
        <<"-poll">> -> 5000;
        _ -> undefined
    end;
default_refresh_for_rem(_) -> undefined.

parse_remediation(#{<<"type">> := <<"array">>, <<"value">> := []}, _D) -> #{};
parse_remediation(R = #{<<"type">> := <<"array">>, <<"value">> := [Rem | Rest]}, D) ->
    maps:merge(parse_remediation(Rem, D),
        parse_remediation(R#{<<"value">> => Rest}, D));

parse_remediation(R = #{<<"name">> := N = <<"redirect-idp">>}, _D) ->
    #{<<"href">> := Href, <<"method">> := MethodBin} = R,
    {Host, Path} = parse_href(Href),
    #{redirect_idp => #remediation{
        name = N,
        method = method_to_atom(MethodBin),
        host = Host,
        path = Path
    }};

parse_remediation(R = #{<<"name">> := <<"challenge-webauthn-autofillui-authenticator">>,
                        <<"relatesTo">> := [_]}, D) ->
    #{challenge_webauthn_autofill := R0} = parse_remediation(
        maps:remove(<<"relatesTo">>, R), D),
    R1 = R0#remediation{authenticator = <<"$.webauthnAutofillUIChallenge">>},
    #{challenge_webauthn_autofill => R1};
parse_remediation(R = #{<<"name">> := <<"device-challenge-poll">>,
                        <<"relatesTo">> := [_]}, D) ->
    #{device_challenge_poll := R0} = parse_remediation(
        maps:remove(<<"relatesTo">>, R), D),
    R1 = R0#remediation{authenticator = <<"$.authenticatorChallenge">>},
    #{device_challenge_poll => R1};

parse_remediation(R = #{<<"name">> := N,
                        <<"href">> := Href,
                        <<"method">> := MethodBin,
                        <<"value">> := Fields0,
                        <<"relatesTo">> := [AuthPath]}, D) ->
    Key = unalias_remediation(N),
    {Host, Path} = parse_href(Href),
    AuthID = auth_ref_to_id(AuthPath, D),
    Fields1 = parse_fields(Fields0, D),
    Refresh = maps:get(<<"refresh">>, R, default_refresh_for_rem(N)),
    #{Key => #remediation{
        name = N,
        method = method_to_atom(MethodBin),
        host = Host,
        path = Path,
        fields = Fields1,
        authenticator = AuthID,
        refresh = Refresh
    }};
parse_remediation(R = #{<<"name">> := N,
                        <<"href">> := Href,
                        <<"method">> := MethodBin,
                        <<"value">> := Fields0}, D) ->
    Key = unalias_remediation(N),
    {Host, Path} = parse_href(Href),
    Fields1 = parse_fields(Fields0, D),
    Refresh = maps:get(<<"refresh">>, R, default_refresh_for_rem(N)),
    #{Key => #remediation{
        name = N,
        method = method_to_atom(MethodBin),
        host = Host,
        path = Path,
        fields = Fields1,
        refresh = Refresh
    }}.

merge_records(T0, _T1, 1) -> T0;
merge_records(T0, T1, N) ->
    case {element(N, T0), element(N, T1)} of
        {undefined, undefined} ->
            merge_records(T0, T1, N - 1);
        {undefined, V} ->
            merge_records(setelement(N, T0, V), T1, N - 1);
        {_V, undefined} ->
            merge_records(T0, T1, N - 1);
        {V0 = [X|_], V1} when is_binary(X) or is_integer(X) ->
            V = sets:to_list(sets:union([sets:from_list(V0), sets:from_list(V1)])),
            merge_records(setelement(N, T0, V), T1, N - 1);
        {V0, V1 = [X|_]} when is_binary(X) or is_integer(X) ->
            V = sets:to_list(sets:union([sets:from_list(V0), sets:from_list(V1)])),
            merge_records(setelement(N, T0, V), T1, N - 1);
        {V0, V1} when is_map(V0) and is_map(V1) ->
            merge_records(setelement(N, T0, maps:merge(V0, V1)), T1, N - 1);
        {_, V} ->
            merge_records(setelement(N, T0, V), T1, N - 1)
    end.

merge_records(T0, T1) when (tuple_size(T0) == tuple_size(T1)) and
                          (element(1, T0) =:= element(1, T1)) ->
    merge_records(T0, T1, tuple_size(T0));
merge_records(T0, T1) ->
    error({mismatched_records, element(1, T0), element(1, T1)}).

do_introspect(S0 = #?MODULE{host = ApiHost, ihdl = Hdl}) ->
    maybe
        {ok, D, S1} ?= post_json(ApiHost, <<"/idp/idx/introspect">>,
            #{<<"interactionHandle">> => Hdl}, S0),
        {ok, {ok, next_steps, RInfo}, S2} ?= parse_response(D, S1),
        {ok, RInfo, S2}
    end.

tokinfo_to_map(#{<<"access_token">> := AT,
                 <<"id_token">> := IT,
                 <<"scope">> := ScopeBin,
                 <<"token_type">> := TokTypeBin}, Claims) ->
    Scopes = [binary_to_atom(X, utf8) || X <-
        binary:split(ScopeBin, <<" ">>, [global])],
    TokenType = binary_to_atom(string:lowercase(TokTypeBin), utf8),
    #{
        claims => Claims,
        access_token => AT,
        id_token => IT,
        scopes => Scopes,
        type => TokenType
    }.


do_get_idp_keys(#remediation{host = Host, path = RemPath},
                #?MODULE{cid = ClientID} = S0) ->
    Path0 = case binary:split(RemPath, <<"/">>, [global]) of
        [<<>>, <<"oauth2">>, <<"v1">> | _] ->
            <<"/oauth2/v1/keys">>;
        [<<>>, <<"oauth2">>, ASID, <<"v1">> | _] ->
            <<"/oauth2/", ASID/binary, "/v1/keys">>
    end,
    Path1 = <<Path0/binary, "?client_id=", ClientID/binary>>,
    case get_json(Host, Path1, S0) of
        {ok, #{<<"keys">> := Keys}, S1} ->
            KeyMap = lists:foldl(fun (#{<<"kid">> := KeyId} = K, Acc) ->
                Acc#{KeyId => K}
            end, #{}, Keys),
            S2 = S1#?MODULE{idpkeys = KeyMap},
            {ok, S2};
        {error, Why, S1} ->
            {error, Why, S1}
    end.

do_issue_token(Rem = #remediation{host = Host, path = Path, method = post}, S0 = #?MODULE{}) ->
    #?MODULE{verifier = CodeVerif, redir = RedirURI} = S0,
    T0 = sign_jwt([<<"https://">>, Host, Path], S0),
    maybe
        {ok, Payload} ?= compose_rem_payload(#{code_verifier => CodeVerif}, Rem, S0),
        Qs0 = maps:to_list(Payload),
        Qs1 = [
            {<<"client_assertion_type">>, <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>},
            {<<"client_assertion">>, T0},
            {<<"redirect_uri">>, RedirURI}
            | Qs0
        ],
        {ok, D, S1} ?= post_formenc(Host, Path, Qs1, S0),
        {ok, D, S1}
    end.

get_prot_keyid(Token, S0) ->
    case jose_jwt:peek_protected(Token) of
        #jose_jws{fields = #{<<"kid">> := KeyId}} -> {ok, KeyId};
        _ -> {error, no_kid_in_jwt, S0}
    end.

get_idp_key(KeyId, S0 = #?MODULE{idpkeys = KM}) ->
    case KM of
        #{KeyId := KeyObj} ->
            Key = jose_jwk:from_map(KeyObj),
            {ok, Key};
        _ ->
            {error, {unknown_idp_key_id, KeyId}, S0}
    end.

verify_jwt(Key, Token, S0 = #?MODULE{}) ->
    case jose_jws:verify(Key, Token) of
        {true, _, _} -> ok;
        {false, _, _} -> {error, jwt_verification_failed, S0}
    end.

do_verify_token(#{<<"id_token">> := AT0}, S0 = #?MODULE{}) ->
    AT = jose_jwt:from_map(jose_jws:expand(AT0)),
    maybe
        {ok, KeyId} ?= get_prot_keyid(AT, S0),
        {ok, Key} ?= get_idp_key(KeyId, S0),
        ok ?= verify_jwt(Key, AT0, S0),
        {_, Payload} = jose_jwt:peek(AT),
        {ok, Payload}
    end.

get_auth_or_enroll(<<"$.currentAuthenticatorEnrollment">>, #?MODULE{curauth = undefined}) ->
    error(no_current_enrollment);
get_auth_or_enroll(<<"$.currentAuthenticatorEnrollment">>, S0 = #?MODULE{curauth = ID}) ->
    get_auth_or_enroll(ID, S0);
get_auth_or_enroll(ID, #?MODULE{authns = A0, enrolls = E0, eauthn = EA0}) ->
    case E0 of
        #{ID := {_Key, _EAuthn, Enroll}} ->
            #{ID := AuthId} = EA0,
            #{AuthId := Authn} = A0,
            {Authn, Enroll};
        _ ->
            case A0 of
                #{ID := Authn} -> Authn;
                _ -> error({unknown_auth_or_enroll_id, ID})
            end
    end.

authenticator_to_common(#authenticator{methods = Methods,
                                       remediations = Rems,
                                       name = Name}) ->
    #{methods => Methods,
      remediations => maps:keys(Rems),
      name => Name}.

map_defined(M0) ->
    maps:filter(fun
        (_K, undefined) -> false;
        (_K, _V) -> true
    end, M0).

authenticator_to_map(A = #authenticator{enrollments = [EnrollId]}, S0) ->
    #?MODULE{enrolls = E0} = S0,
    #{EnrollId := {_Key, _EAuthn, Enroll}} = E0,
    authenticator_to_map({A, Enroll}, S0);

authenticator_to_map({A = #authenticator{}, #password_enroll{}}, _S0) ->
    {password, authenticator_to_common(A), #{}};
authenticator_to_map({A = #authenticator{}, E = #device_loopback_enroll{}}, _S0) ->
    #device_loopback_enroll{challenge = Chal, domain = Domain, ports = Ports,
                            timeout = Timeout} = E,
    Info = map_defined(#{challenge => Chal, domain => Domain, ports => Ports,
                         timeout => Timeout}),
    {loopback_device, authenticator_to_common(A), Info};
authenticator_to_map({A = #authenticator{}, #device_uri_enroll{href = U}}, _S0) ->
    {custom_uri_device, authenticator_to_common(A), #{uri => U}};
authenticator_to_map({A = #authenticator{}, #email_enroll{email = E}}, _S0) ->
    {email, authenticator_to_common(A), #{email => E}};
authenticator_to_map({A = #authenticator{}, #phone_enroll{number = N}}, _S0) ->
    {phone, authenticator_to_common(A), #{number => N}};
authenticator_to_map({A = #authenticator{},
                      #secq_enroll{question = Q, answer = A}}, _S0) ->
    {secq, authenticator_to_common(A),
     map_defined(#{question => Q, answer => A})};
authenticator_to_map({A = #authenticator{},
                      #app_enroll{device_name = Name, push_code = Code}}, _S0) ->
    {app, authenticator_to_common(A),
     map_defined(#{device_name => Name, push_code => Code})};

authenticator_to_map({A = #authenticator{}, E = #webauthn_enroll{}}, _S0) ->
    #webauthn_enroll{device_name = DevName, cred_id = CredId, aaguid = AAGuid,
                     challenge = Chal, appid = AppId, uvreq = UVReq} = E,
    {webauthn, authenticator_to_common(A),
     map_defined(#{device_name => DevName, cred_id => CredId, aaguid => AAGuid,
                   challenge => Chal, app_id => AppId, uv_required => UVReq})}.

field_to_map(#simple_field{required = Req, visible = Vis, default = Def, label = Lbl}, _S0) ->
    {simple, map_defined(
        #{required => Req, visible => Vis, default => Def, label => Lbl})};

field_to_map(#object_field{required = Req, fields = SubFields}, S0) ->
    {object, #{required => Req, properties => fields_to_map(SubFields, S0)}};

field_to_map(#options_field{required = Req, options = Opts0}, S0) ->
    Opts1 = maps:fold(fun

        (K, #object_option{authenticator = undefined, fields = F}, Acc) ->
            [#{label => K, properties => fields_to_map(F, S0)} | Acc];
        (K, #object_option{authenticator = AID, fields = F}, Acc) ->
            A = get_auth_or_enroll(AID, S0),
            [#{label => K, authenticator => authenticator_to_map(A, S0),
               properties => fields_to_map(F, S0)} | Acc];

        (K, #string_option{value = V}, Acc) when K =:= V ->
            Acc;
        (K, #string_option{authenticator = undefined, value = V}, Acc) ->
            [#{label => K, value => V} | Acc];
        (K, #string_option{authenticator = AID, value = V}, Acc) ->
            A = get_auth_or_enroll(AID, S0),
            [#{label => K, value => V,
               authenticator => authenticator_to_map(A, S0)} | Acc]

    end, [], Opts0),
    {choice, #{required => Req}, Opts1}.

fields_to_map(FieldMap, S0) ->
    maps:fold(fun (KBin, Field, Acc) ->
        K = field_name_to_atom(KBin),
        case Field of
            #simple_field{mutable = false} -> Acc;
            _ -> Acc#{K => field_to_map(Field, S0)}
        end
    end, #{}, FieldMap).

remediation_to_map(R = #remediation{}, S0 = #?MODULE{}) ->
    #remediation{name = Name, authenticator = AID, fields = Fields,
                 refresh = Refresh} = R,
    M0 = #{name => Name, properties => fields_to_map(Fields, S0)},
    M1 = case AID of
        undefined -> M0;
        _ ->
            A = get_auth_or_enroll(AID, S0),
            M0#{authenticator => authenticator_to_map(A, S0)}
    end,
    M2 = case Refresh of
        undefined -> M1;
        _ -> M1#{refresh => Refresh}
    end,
    M2.

windows_build_to_ua(B) when B >= 30000 -> <<"Windows NT 10.0; Windows 11">>;
windows_build_to_ua(B) when B >= 28000 -> <<"Windows NT 10.0; Windows 11 26H2">>;
windows_build_to_ua(B) when B >= 26200 -> <<"Windows NT 10.0; Windows 11 25H2">>;
windows_build_to_ua(B) when B >= 26100 -> <<"Windows NT 10.0; Windows 11 24H2">>;
windows_build_to_ua(B) when B >= 22631 -> <<"Windows NT 10.0; Windows 11 23H2">>;
windows_build_to_ua(B) when B >= 22621 -> <<"Windows NT 10.0; Windows 11 22H2">>;
windows_build_to_ua(B) when B >= 22000 -> <<"Windows NT 10.0; Windows 11 21H2">>;
windows_build_to_ua(B) when B >= 19045 -> <<"Windows NT 10.0; Windows 10 22H2">>;
windows_build_to_ua(B) when B >= 19044 -> <<"Windows NT 10.0; Windows 10 21H2">>;
windows_build_to_ua(B) when B >= 19043 -> <<"Windows NT 10.0; Windows 10 21H1">>;
windows_build_to_ua(B) when B >= 19042 -> <<"Windows NT 10.0; Windows 10 20H2">>;
windows_build_to_ua(B) when B >= 19041 -> <<"Windows NT 10.0; Windows 10 2004">>;
windows_build_to_ua(B) when B >= 18363 -> <<"Windows NT 10.0; Windows 10 1909">>;
windows_build_to_ua(B) when B >= 18362 -> <<"Windows NT 10.0; Windows 10 1903">>;
windows_build_to_ua(B) when B >= 17763 -> <<"Windows NT 10.0; Windows 10 1809">>;
windows_build_to_ua(B) when B >= 17134 -> <<"Windows NT 10.0; Windows 10 1803">>;
windows_build_to_ua(B) when B >= 16299 -> <<"Windows NT 10.0; Windows 10 1709">>;
windows_build_to_ua(B) when B >= 15063 -> <<"Windows NT 10.0; Windows 10 1703">>;
windows_build_to_ua(B) when B >= 14393 -> <<"Windows NT 10.0; Windows 10 1607">>;
windows_build_to_ua(B) when B >= 10240 -> <<"Windows NT 10.0; Windows 10 1507">>;
windows_build_to_ua(B) when B >= 9600 -> <<"Windows NT 6.2; Windows 8">>;
windows_build_to_ua(B) when B >= 7601 -> <<"Windows NT 6.1; Windows 7 SP1">>;
windows_build_to_ua(B) when B >= 7600 -> <<"Windows NT 6.1; Windows 7">>;
windows_build_to_ua(B) when B >= 6002 -> <<"Windows NT 6.0; Windows Vista SP2">>;
windows_build_to_ua(B) when B >= 6001 -> <<"Windows NT 6.0; Windows Vista SP1">>;
windows_build_to_ua(B) when B >= 2600 -> <<"Windows NT 5.1; Windows XP">>;
windows_build_to_ua(_B) -> <<"Windows NT; Version Unknown">>.

macos_rdp_build_to_ua(B) when B >= 2814 -> <<"Macintosh; Intel Mac OS X 10_13_0; Win App 11.3">>;
macos_rdp_build_to_ua(B) when B >= 2667 -> <<"Macintosh; Intel Mac OS X 10_12_0; Win App 11.2">>;
macos_rdp_build_to_ua(B) when B >= 2508 -> <<"Macintosh; Intel Mac OS X 10_12_0; Win App 11.1">>;
macos_rdp_build_to_ua(B) when B >= 2372 -> <<"Macintosh; Intel Mac OS X 10_12_0; Win App 11.0">>;
macos_rdp_build_to_ua(_B) -> <<"Macintosh; Intel Mac OS X 10_12_0; Remote Desktop 10.x">>.

build_ua(ClientMeta) ->
    UA0 = [<<"Mozilla/5.0">>],
    UA1 = case ClientMeta of
        #{os_type := windows, os_build := B} ->
            [<<")">>, windows_build_to_ua(B), <<" (">> | UA0];
        #{os_type := osx, os_build := B} when (B band 16#f0000) == 16#10000 ->
            [<<")">>, macos_rdp_build_to_ua(B band 16#ffff), <<" (">> | UA0];
        #{os_type := ios, os_build := B} when (B band 16#f0000) == 16#10000 ->
            [<<" (Macintosh; Mac OS X; actually iOS)">> | UA0];
        #{os_type := unix, os_subtype := native_x11} ->
            [<<" (X11; Linux x86_64; FreeRDP)">> | UA0];
        #{os_type := unix, os_subtype := unknown} ->
            [<<" (Linux x86_64)">> | UA0];
        _ ->
            [<<" (Unknown)">> | UA0]
    end,
    UA2 = case ClientMeta of
        #{os_type := AppleOS, os_build := BN} when (AppleOS =:= osx) or (AppleOS =:= ios) ->
            [integer_to_binary(BN band 16#ffff), <<" ClientBuild/">> | UA1];
        #{os_build := BN} ->
            [integer_to_binary(BN), <<" ClientBuild/">> | UA1];
        _ -> UA1
    end,
    UA3 = case ClientMeta of
        #{rdp_version := {Maj, Min}} ->
            [integer_to_binary(Min), <<".">>, integer_to_binary(Maj), <<" RDP/">> | UA2];
        _ ->
            UA2
    end,
    iolist_to_binary(lists:reverse([<<" rdpproxy/1.0">> | UA3])).

sign_jwt(Endpoint, #?MODULE{cid = ClientID, key = JWK}) ->
    T0Signed = jose_jwt:sign(JWK, #{
        <<"aud">> => iolist_to_binary(Endpoint),
        <<"exp">> => erlang:system_time(second)+600,
        <<"iss">> => ClientID,
        <<"sub">> => ClientID
    }),
    {_, T0} = jose_jws:compact(T0Signed),
    T0.

get_remediation(RemType, S0 = #?MODULE{rems = Rems}) ->
    case Rems of
        #{RemType := Rem = #remediation{}} ->
            {ok, Rem};
        _ ->
            {error, {invalid_remediation, RemType}, S0}
    end.

handle_call(remediations, _From, S0 = #?MODULE{rems = Rems}) ->
    {reply, {ok, maps:keys(Rems)}, S0};

handle_call({remediation_info, Name}, _From, S0 = #?MODULE{rems = Rems}) ->
    case Rems of
        #{Name := Rem} ->
            {reply, {ok, remediation_to_map(Rem, S0)}, S0};
        _ ->
            {reply, {error, not_found}, S0}
    end;

handle_call(get_messages, _From, S0 = #?MODULE{msgs = Msgs}) ->
    {reply, {ok, [msg_to_tuple(M) || M <- Msgs]}, S0};

handle_call(authenticator_info, _From, S0 = #?MODULE{curauth = undefined}) ->
    {reply, {error, no_current_authenticator}, S0};
handle_call(authenticator_info, _From, S0 = #?MODULE{curauth = EID}) ->
    A = get_auth_or_enroll(EID, S0),
    Info = authenticator_to_map(A, S0),
    {reply, {ok, Info}, S0};

handle_call(begin_auth, From, S0 = #?MODULE{}) ->
    handle_call({begin_auth, #{}}, From, S0);
handle_call({begin_auth, Opts}, _From, S0 = #?MODULE{}) ->
    #?MODULE{host = ApiHost, cid = ClientID, redir = RedirURI} = S0,

    LoginHint = maps:get(login_hint, Opts, undefined),

    AddHeaders0 = #{<<"user-agent">> => build_ua(Opts)},
    AddHeaders1 = case Opts of
        #{client_ip := IP} -> AddHeaders0#{<<"x-forwarded-for">> => IP};
        _ -> AddHeaders0
    end,
    AddHeaders2 = case Opts of
        #{device_id := DevID} -> AddHeaders1#{<<"x-device-token">> => DevID};
        _ -> AddHeaders1
    end,

    T0 = sign_jwt([<<"https://">>, ApiHost, <<"/oauth2/default/v1/interact">>], S0),

    CodeVerif = jose_base64url:encode(crypto:strong_rand_bytes(32)),
    CodeChal = jose_base64url:encode(crypto:hash(sha256, CodeVerif)),

    S1 = S0#?MODULE{verifier = CodeVerif, addhdrs = AddHeaders2},

    HintQ = case LoginHint of
        undefined -> [];
        _ -> [{<<"login_hint">>, LoginHint}]
    end,
    Qs = [
        {<<"client_id">>, ClientID},
        {<<"scope">>, <<"openid profile">>},
        {<<"client_assertion_type">>, <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>},
        {<<"client_assertion">>, T0},
        {<<"state">>, <<"null">>},
        {<<"redirect_uri">>, RedirURI},
        {<<"code_challenge_method">>, <<"S256">>},
        {<<"code_challenge">>, CodeChal}
        | HintQ
    ],
    err2reply(maybe
        {ok, #{<<"interaction_handle">> := Hdl0}, S2} ?=
            post_formenc(ApiHost, <<"/oauth2/default/v1/interact">>, Qs, S1),
        S3 = S2#?MODULE{ihdl = Hdl0},
        {ok, RInfo, S4} ?= do_introspect(S3),
        {reply, {ok, next_steps, RInfo}, S4}
    end);

handle_call(RemType, From, S0 = #?MODULE{}) when is_atom(RemType) ->
    handle_call({RemType, #{}}, From, S0);
handle_call({RemType, Args}, _From, S0 = #?MODULE{}) when is_atom(RemType) and is_map(Args) ->
    err2reply(maybe
        {ok, Rem} ?= get_remediation(RemType, S0),
        #remediation{host = Host, path = Path, method = post} = Rem,
        {ok, Payload} ?= compose_rem_payload(Args, Rem, S0),
        {ok, D, S1} ?= post_json(Host, Path, Payload, S0),
        {ok, Reply, S2} ?= parse_response(D, S1),
        {reply, Reply, S2}
    end).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

field_name_to_atom_test() ->
    ?assertMatch('test123_why', field_name_to_atom(<<"test123Why">>)),
    ?assertMatch(okta_thing_when_happy, field_name_to_atom(<<"okta-thingWhenHappy">>)).

parse_enrollments_basic_test() ->
    D0 = #{
        <<"authenticatorEnrollments">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"pfd7n5i4xyWwnZ7ff3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}],
                    <<"profile">> => #{<<"deviceName">> => <<"Foo Bar">>}
                }
            ]
        },
        <<"authenticators">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"aut5cc88xdpzAn7jD3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}]
                }
            ]
        }
    },
    S0 = #?MODULE{},
    S1 = parse_enrollments(D0, S0),
    #?MODULE{enrolls = E1, authns = A1, eauthn = EA1, curauth = CA1} = S1,
    ?assertMatch(#{<<"pfd7n5i4xyWwnZ7ff3l7">> :=
        {<<"okta_verify">>, #authenticator{}, #app_enroll{}}}, E1),
    ?assertMatch([<<"pfd7n5i4xyWwnZ7ff3l7">>], maps:keys(E1)),
    ?assertMatch([], maps:keys(A1)),
    ?assertMatch([], maps:keys(EA1)),
    ?assertMatch(undefined, CA1).

parse_curenrollment_no_id_test() ->
    D0 = #{
        <<"currentAuthenticatorEnrollment">> => #{
            <<"type">> => <<"object">>,
            <<"value">> => #{
                <<"key">> => <<"okta_verify">>,
                <<"type">> => <<"app">>,
                <<"displayName">> => <<"Okta Verify">>,
                <<"methods">> => [#{<<"type">> => <<"push">>}],
                <<"contextualData">> => #{
                    <<"correctAnswer">> => <<"00">>
                }
            }
        },
        <<"authenticators">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"aut5cc88xdpzAn7jD3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}]
                }
            ]
        }
    },
    S0 = #?MODULE{},
    S1 = parse_enrollments(D0, S0),
    #?MODULE{enrolls = E1, authns = A1, eauthn = EA1, curauth = CA1} = S1,
    ?assertMatch(#{<<"okta_verify">> :=
        {<<"okta_verify">>, #authenticator{}, #app_enroll{}}}, E1),
    ?assertMatch([<<"okta_verify">>], maps:keys(E1)),
    ?assertMatch([], maps:keys(A1)),
    ?assertMatch([], maps:keys(EA1)),
    ?assertMatch(<<"okta_verify">>, CA1).

parse_enrollments_and_authenticators_basic_test() ->
    D0 = #{
        <<"authenticatorEnrollments">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"pfd7n5i4xyWwnZ7ff3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}],
                    <<"profile">> => #{<<"deviceName">> => <<"Foo Bar">>}
                }
            ]
        },
        <<"authenticators">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"aut5cc88xdpzAn7jD3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}]
                }
            ]
        }
    },
    S0 = #?MODULE{},
    S1 = parse_enrollments(D0, S0),
    S2 = parse_authenticators(D0, S1),
    #?MODULE{enrolls = E1, authns = A1, eauthn = EA1, curauth = CA1} = S2,
    ?assertMatch(#{<<"pfd7n5i4xyWwnZ7ff3l7">> :=
        {<<"okta_verify">>, #authenticator{}, #app_enroll{}}}, E1),
    ?assertMatch([<<"pfd7n5i4xyWwnZ7ff3l7">>], maps:keys(E1)),
    ?assertMatch(#{<<"aut5cc88xdpzAn7jD3l7">> :=
        #authenticator{enrollments = [<<"pfd7n5i4xyWwnZ7ff3l7">>]}}, A1),
    ?assertMatch([<<"aut5cc88xdpzAn7jD3l7">>], maps:keys(A1)),
    ?assertMatch(#{<<"pfd7n5i4xyWwnZ7ff3l7">> := <<"aut5cc88xdpzAn7jD3l7">>}, EA1),
    ?assertMatch([<<"pfd7n5i4xyWwnZ7ff3l7">>], maps:keys(EA1)),
    ?assertMatch(undefined, CA1).

parse_enrollments_and_authenticators_multi_test() ->
    D0 = #{
        <<"authenticatorEnrollments">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"pfd7n5i4xyWwnZ7ff3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}],
                    <<"profile">> => #{<<"deviceName">> => <<"Foo Bar">>}
                },
                #{
                    <<"id">> => <<"pfd7n5i4xyWwnZ7aa99a">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}],
                    <<"profile">> => #{<<"deviceName">> => <<"Foo Test">>}
                }
            ]
        },
        <<"authenticators">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"aut5cc88xdpzAn7jD3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}]
                }
            ]
        }
    },
    S0 = #?MODULE{},
    S1 = parse_enrollments(D0, S0),
    S2 = parse_authenticators(D0, S1),
    #?MODULE{enrolls = E1, authns = A1, eauthn = EA1, curauth = CA1} = S2,
    ?assertMatch(#{
        <<"pfd7n5i4xyWwnZ7ff3l7">> :=
            {<<"okta_verify">>, #authenticator{},
             #app_enroll{device_name = <<"Foo Bar">>}},
        <<"pfd7n5i4xyWwnZ7aa99a">> :=
            {<<"okta_verify">>, #authenticator{},
             #app_enroll{device_name = <<"Foo Test">>}}
        }, E1),
    ?assertMatch([<<"pfd7n5i4xyWwnZ7aa99a">>, <<"pfd7n5i4xyWwnZ7ff3l7">>], maps:keys(E1)),
    ?assertMatch(#{<<"aut5cc88xdpzAn7jD3l7">> :=
        #authenticator{enrollments = [<<"pfd7n5i4xyWwnZ7aa99a">>, <<"pfd7n5i4xyWwnZ7ff3l7">>]}}, A1),
    ?assertMatch([<<"aut5cc88xdpzAn7jD3l7">>], maps:keys(A1)),
    ?assertMatch(#{<<"pfd7n5i4xyWwnZ7ff3l7">> := <<"aut5cc88xdpzAn7jD3l7">>,
                   <<"pfd7n5i4xyWwnZ7aa99a">> := <<"aut5cc88xdpzAn7jD3l7">>}, EA1),
    ?assertMatch([<<"pfd7n5i4xyWwnZ7aa99a">>, <<"pfd7n5i4xyWwnZ7ff3l7">>], maps:keys(EA1)),
    ?assertMatch(undefined, CA1).

parse_curauthenticator_no_id_test() ->
    D0 = #{
        <<"currentAuthenticator">> => #{
            <<"type">> => <<"object">>,
            <<"value">> => #{
                <<"id">> => <<"aut5cc88xdpzAn7jD3l7">>,
                <<"key">> => <<"okta_verify">>,
                <<"type">> => <<"app">>,
                <<"displayName">> => <<"Okta Verify">>,
                <<"methods">> => [#{<<"type">> => <<"push">>}],
                <<"contextualData">> => #{
                    <<"correctAnswer">> => <<"00">>
                }
            }
        },
        <<"authenticatorEnrollments">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"pfd7n5i4xyWwnZ7ff3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}, #{<<"type">> => <<"totp">>}],
                    <<"profile">> => #{<<"deviceName">> => <<"Foo Bar">>}
                },
                #{
                    <<"id">> => <<"pfd7n5i4xyWwnZ7ff9aa">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}, #{<<"type">> => <<"totp">>}],
                    <<"profile">> => #{<<"deviceName">> => <<"Foo Test">>}
                }
            ]
        },
        <<"authenticators">> => #{
            <<"type">> => <<"array">>,
            <<"value">> => [
                #{
                    <<"id">> => <<"aut5cc88xdpzAn7jD3l7">>,
                    <<"key">> => <<"okta_verify">>,
                    <<"type">> => <<"app">>,
                    <<"displayName">> => <<"Okta Verify">>,
                    <<"methods">> => [#{<<"type">> => <<"push">>}, #{<<"type">> => <<"totp">>}]
                }
            ]
        }
    },
    S0 = #?MODULE{},
    S1 = parse_enrollments(D0, S0),
    S2 = parse_authenticators(D0, S1),
    #?MODULE{enrolls = E1, authns = A1, eauthn = EA1, curauth = CA1} = S2,
    ?assertMatch(#{
        <<"pfd7n5i4xyWwnZ7ff3l7">> :=
            {<<"okta_verify">>, #authenticator{},
             #app_enroll{push_code = <<"00">>, device_name = <<"Foo Bar">>}},
        <<"pfd7n5i4xyWwnZ7ff9aa">> :=
            {<<"okta_verify">>, #authenticator{},
             #app_enroll{push_code = <<"00">>, device_name = <<"Foo Test">>}}
        }, E1),
    ?assertMatch([<<"pfd7n5i4xyWwnZ7ff3l7">>, <<"pfd7n5i4xyWwnZ7ff9aa">>], maps:keys(E1)),
    ?assertMatch(#{<<"aut5cc88xdpzAn7jD3l7">> :=
        #authenticator{methods = [push],
                       enrollments = [<<"pfd7n5i4xyWwnZ7ff3l7">>, <<"pfd7n5i4xyWwnZ7ff9aa">>]}
                       }, A1),
    ?assertMatch([<<"aut5cc88xdpzAn7jD3l7">>], maps:keys(A1)),
    ?assertMatch([<<"pfd7n5i4xyWwnZ7ff3l7">>, <<"pfd7n5i4xyWwnZ7ff9aa">>], maps:keys(EA1)),
    ?assertMatch(<<"pfd7n5i4xyWwnZ7ff3l7">>, CA1),

    ?assertMatch(#authenticator{},
        get_auth_or_enroll(<<"aut5cc88xdpzAn7jD3l7">>, S2)),
    ?assertMatch({#authenticator{}, #app_enroll{push_code = <<"00">>}},
        get_auth_or_enroll(<<"pfd7n5i4xyWwnZ7ff3l7">>, S2)).


map_remprops_test() ->
    RemProps0 = #{
        credentials => {object, #{required => true, properties => #{
            passcode => {simple, #{required => true}}
        }}}
    },
    Fun0 = fun
        ([passcode, credentials], {simple, #{required := true}}) ->
            <<"abc123">>
    end,
    A0 = map_remprops(Fun0, RemProps0),
    ?assertMatch(#{credentials := #{passcode := <<"abc123">>}}, A0),
    ?assertMatch([credentials], maps:keys(A0)),
    A1 = map_remprops(Fun0, RemProps0, [simple_only]),
    ?assertMatch(A0, A1),
    A2 = map_remprops(Fun0, RemProps0, [required_only]),
    ?assertMatch(A0, A1),

    RemProps1 = #{
        credentials => {object, #{required => true, properties => #{
            passcode => {simple, #{required => false}},
            something => {simple, #{required => true}}
        }}},
        type => {choice, #{required => true}, [
            #{label => <<"Type 1">>, value => <<"type1">>},
            #{label => <<"Type 2">>, value => <<"type2">>}
        ]}
    },
    A3 = map_remprops(fun
        ([passcode, credentials], {simple, #{required := false}}) ->
            <<"abc123">>;
        ([something, credentials], {simple, #{required := true}}) ->
            <<"def456">>;
        ([type], {choice, _, Opts}) ->
            <<"Type 1">>
    end, RemProps1),
    ?assertMatch(#{
        credentials := #{
            passcode := <<"abc123">>,
            something := <<"def456">>
        },
        type := <<"Type 1">>
        }, A3),
    Fun2 = fun
        ([something, credentials], {simple, #{required := true}}) ->
            <<"def456">>;
        ([type], {choice, _, Opts}) ->
            <<"Type 1">>
    end,
    A4 = map_remprops(Fun2, RemProps1, [required_only]),
    ?assertMatch(#{
        credentials := #{something := <<"def456">>},
        type := <<"Type 1">>
        }, A4),
    ?assertError({choice_required, [type]},
        map_remprops(Fun2, RemProps1, [simple_only])).

mapfold_remprops_test() ->
    RemProps0 = #{
        credentials => {object, #{required => true, properties => #{
            passcode => {simple, #{required => true}},
            foobar => {simple, #{required => true}},
            test => {object, #{required => true, properties => #{
                thing => {simple, #{required => true}}
            }}}
        }}}
    },
    Fun0 = fun (Path, _PropInfo, Acc) -> {nope, [Path | Acc]} end,
    {A0, L0} = mapfold_remprops(Fun0, [], RemProps0),
    ?assertMatch(#{
        credentials := #{
            passcode := nope,
            foobar := nope,
            test := #{thing := nope}
        }}, A0),
    ?assertMatch([
        [foobar, credentials], [passcode, credentials], [thing, test, credentials]
        ], L0).

-endif.
