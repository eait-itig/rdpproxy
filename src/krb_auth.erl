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

-module(krb_auth).

-export([authenticate/1]).

-include_lib("kerlberos/include/KRB5.hrl").
-include_lib("kerlberos/include/ms_pac.hrl").

record_failure(Stage, Reason) ->
    case erlang:get(conn_ra_sid) of
        undefined -> ok;
        Sid ->
            Attempt0 = erlang:get(conn_ra_attempt),
            Attempt1 = Attempt0#{
                status => failure,
                stage => Stage,
                reason => Reason,
                time => erlang:system_time(second)
            },
            conn_ra:auth_attempt(Sid, Attempt1)
    end.

-type user_info() :: #{
    username => binary(),
    password => binary(),
    groups => [krb_ms_pac:sid()]
    }.

-type tgts() :: #{string() => krb_proto:ticket()}.

-record(realm_state, {
    pid :: pid(),
    tgt :: krb_proto:ticket()
    }).

-record(?MODULE, {
    realm :: undefined | string(),
    realms = #{} :: #{string() => #realm_state{}},
    svctkt :: undefined | krb_proto:ticket(),
    uinfo :: user_info(),
    lasterr :: any()
    }).

eval_step({all_of, []}, S0 = #?MODULE{}) ->
    {ok, S0};
eval_step({all_of, [Next | Rest]}, S0 = #?MODULE{}) ->
    case eval_step(Next, S0) of
        E = {error, _} -> E;
        {ok, S1} -> eval_step({all_of, Rest}, S1)
    end;
eval_step({any_of, []}, #?MODULE{lasterr = Err}) ->
    Err;
eval_step({any_of, [Next | Rest]}, S0 = #?MODULE{}) ->
    case eval_step(Next, S0) of
        E = {error, _} ->
            eval_step({any_of, Rest}, S0#?MODULE{lasterr = E});
        {ok, S1} ->
            {ok, S1}
    end;
eval_step(danger_testing_only_always_allow, S0 = #?MODULE{}) ->
    {ok, S0};
eval_step({authenticate, Opts}, S0 = #?MODULE{uinfo = UInfo0}) ->
    #?MODULE{realms = Rs0} = S0,
    OptsMap = maps:from_list(Opts),
    #{realm := N} = OptsMap,
    #{username := User, password := Password} = UInfo0,
    Principal = [unicode:characters_to_list(User, utf8)],
    {ok, Realm} = krb_realm:open(N),
    case krb_realm:authenticate(Realm, Principal, Password) of
        {ok, TGT} ->
            lager:debug("authenticated as ~s@~s", [User, N]),
            Rec = #realm_state{pid = Realm, tgt = TGT},
            Rs1 = Rs0#{N => Rec},
            S1 = S0#?MODULE{realm = N, realms = Rs1},
            {ok, S1};
        {error, Why} ->
            lager:debug("authentication failure as ~s@~s: ~p",
                [User, N, Why]),
            {error, {{realm, N}, Why}}
    end;
eval_step({cross_realm, Opts}, S0 = #?MODULE{realms = Rs0}) ->
    OptsMap = maps:from_list(Opts),
    #{to_realm := R1} = OptsMap,
    R0 = maps:get(from_realm, OptsMap, S0#?MODULE.realm),
    #{R0 := #realm_state{pid = Realm0, tgt = TGT0}} = Rs0,
    {ok, Realm1} = krb_realm:open(R1),
    SvcPrincipal = ["krbtgt", R1],
    case krb_realm:obtain_ticket(Realm0, TGT0, SvcPrincipal) of
        {ok, TGT1} ->
            Rec = #realm_state{pid = Realm1, tgt = TGT1},
            Rs1 = Rs0#{R1 => Rec},
            S1 = S0#?MODULE{realm = R1, realms = Rs1},
            {ok, S1};
        {error, Why} ->
            #?MODULE{uinfo = #{username := U}} = S0,
            lager:debug("cross-realm failure as ~s (~s to ~s): ~p",
                [U, R0, R1, Why]),
            {error, {{cross_realm, R0, R1}, Why}}
    end;
eval_step({get_service_ticket, Opts}, S0 = #?MODULE{realms = Rs0}) ->
    OptsMap = maps:from_list(Opts),
    #{principal := SvcPrincipal} = OptsMap,
    R = maps:get(realm, OptsMap, S0#?MODULE.realm),
    #{R := #realm_state{pid = Realm, tgt = TGT}} = Rs0,
    case krb_realm:obtain_ticket(Realm, TGT, SvcPrincipal) of
        {ok, SvcTicket} ->
            S1 = S0#?MODULE{svctkt = SvcTicket},
            {ok, S1};
        {error, Why} ->
            #?MODULE{uinfo = #{username := U}} = S0,
            lager:debug("service ticket (~p) failure as ~s@~s: ~p",
                [SvcPrincipal, U, R, Why]),
            {error, {{service_tkt, SvcPrincipal, R}, Why}}
    end;
eval_step({check_service_ticket, _Opts}, _S0 = #?MODULE{svctkt = undefined}) ->
    {error, no_service_ticket};
eval_step({check_service_ticket, Opts}, S0 = #?MODULE{svctkt = SvcTkt0}) ->
    OptsMap = maps:from_list(Opts),
    #{keytab := KeyTabPath} = OptsMap,
    {ok, Data} = file:read_file(KeyTabPath),
    {ok, KeyTab} = krb_mit_keytab:parse(Data),
    #{ticket := SvcTicket0} = SvcTkt0,
    {ok, Keys} = krb_mit_keytab:filter_for_ticket(KeyTab, SvcTicket0),
    case krb_proto:decrypt(Keys, kdc_rep_ticket, SvcTicket0) of
        {ok, SvcTicket1 = #'Ticket'{'enc-part' = EP}} ->
            #?MODULE{uinfo = UInfo0} = S0,
            #{username := User} = UInfo0,
            OurPrincipal = [unicode:characters_to_list(User, utf8)],
            #'EncTicketPart'{cname = CName} = EP,
            #'PrincipalName'{'name-string' = TheirPrincipal} = CName,
            if
                (OurPrincipal =/= TheirPrincipal) ->
                    {error, {princ_mismatch, OurPrincipal, TheirPrincipal}};
                (OurPrincipal =:= TheirPrincipal) ->
                    SvcTkt1 = SvcTkt0#{ticket => SvcTicket1},
                    S1 = S0#?MODULE{svctkt = SvcTkt1},
                    {ok, S1}
            end;
        {error, Why} ->
            {error, {decrypt_ticket, Why}}
    end;
eval_step({check_pac, Opts}, S0 = #?MODULE{svctkt = SvcTkt}) ->
    OptsMap = maps:from_list(Opts),
    Required = maps:get(required, OptsMap, true),
    #{ticket := SvcTicket} = SvcTkt,
    case krb_ms_pac:decode_ticket(SvcTicket) of
        {ok, #pac{buffers = Bufs}} ->
            #?MODULE{uinfo = UInfo0} = S0,
            Groups0 = maps:get(groups, UInfo0, []),
            #pac_logon_info{info = LogonInfo} = lists:keyfind(pac_logon_info, 1, Bufs),
            #kerb_validation_info{logon_domain_id = DSid, group_ids = GMs} = LogonInfo,
            GroupSids = [
                DSid ++ [RId]
                || #group_membership{relative_id = RId} <- GMs
            ],
            UInfo1 = UInfo0#{groups => Groups0 ++ GroupSids},
            S1 = S0#?MODULE{uinfo = UInfo1},
            {ok, S1};
        {error, no_pac} when not Required ->
            {ok, S0};
        Err = {error, _} ->
            Err
    end.


-spec authenticate(user_info()) -> false | {true, user_info(), tgts()}.
authenticate(#{username := U, password := P} = Args) ->
    Krb5Config = application:get_env(rdpproxy, krb5, []),

    UInfo0 = #{username => U, password => P},

    BaseAttempt = #{username => U, time => erlang:system_time(second)},
    case Args of
        #{session := Sid} ->
            erlang:put(conn_ra_sid, Sid),
            erlang:put(conn_ra_attempt, BaseAttempt),
            conn_ra:auth_attempt(Sid, BaseAttempt);
        _ ->
            erlang:erase(conn_ra_sid)
    end,

    S0 = #?MODULE{uinfo = UInfo0},
    case eval_step(Krb5Config, S0) of
        {ok, #?MODULE{uinfo = UInfo1, realms = Rs}} ->
            UInfo2 = maps:remove(username, UInfo1),
            UInfo3 = maps:remove(password, UInfo2),
            UInfo4 = UInfo3#{user => U},
            case Args of
                #{session := CSid} ->
                    Attempt = #{
                        username => U,
                        status => success,
                        time => erlang:system_time(second)
                    },
                    conn_ra:auth_attempt(CSid, Attempt);
                _ -> ok
            end,
            Tgts = maps:map(fun (K, #realm_state{tgt = TGT}) -> TGT end, Rs),
            {true, UInfo4, Tgts};
        {error, Why} ->
            lager:debug("failed auth for ~s: ~p", [U, Why]),
            record_failure(krb5_login, Why),
            false
    end.
