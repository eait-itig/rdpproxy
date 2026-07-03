%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2026 Lexi Wilson <lexi@uq.edu.au>
%% The University of Queensland
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

-module(scard_auth_fsm).

-compile([{parse_transform, lager_transform}]).

-behaviour(gen_statem).

-include_lib("public_key/include/public_key.hrl").
-define('szOID_NT_PRINCIPAL_NAME', {1,3,6,1,4,1,311,20,2,3}).

-include_lib("rdp_proto/include/rdpdr.hrl").
-include_lib("rdpproxy/include/PKCS7.hrl").

% user api
-export([
    start_link/2,
    list_cards/1,
    get_card/2,
    get_slot/3,
    list_valid_slots/1,
    transaction/3,
    stop/1
    ]).

% fsm state callbacks
-export([
    open_scard/3,
    no_scard/3,
    enum_cards/3,
    enum_slots/3,
    no_cards/3,
    validate_certs/3,
    ready/3
    ]).
-export([init/1, terminate/3, callback_mode/0]).

-type card_id() :: binary().
-type slot_id() :: nist_piv:slot().
-type pin() :: binary().
-type epw() :: scard_saved_pw_ra:encrypted_pw().
-type pw() :: scard_saved_pw_ra:password().
-type ui_fsm() :: pid().
-type fsm() :: pid().

-export_type([
    card_info/0,
    slot_info/0,
    fsm/0,
    card_id/0,
    slot_id/0
    ]).

-spec start_link(rdp_server:server(), ui_fsm()) -> {ok, fsm()} | {error, term()}.
start_link(Srv, UiFsm) ->
    gen_statem:start_link(?MODULE, [Srv, UiFsm], []).

-spec stop(fsm()) -> ok | {error, term()}.
stop(Pid) ->
    gen_statem:cast(Pid, stop).

-spec list_cards(fsm()) -> {ok, [card_info()]} | {error, term()}.
list_cards(Pid) ->
    gen_statem:call(Pid, list_cards).

-spec get_card(fsm(), card_id()) -> {ok, card_info()} | {error, not_found} | {error, term()}.
get_card(Pid, Card) ->
    gen_statem:call(Pid, {get_card, Card}).

-spec get_slot(fsm(), card_id(), slot_id()) -> {ok, card_info(), slot_info()} | {error, not_found} | {error, term()}.
get_slot(Pid, Card, Slot) ->
    gen_statem:call(Pid, {get_slot, Card, Slot}).

-spec list_valid_slots(fsm()) -> {ok, [slot_info()]} | {error, term()}.
list_valid_slots(Pid) ->
    gen_statem:call(Pid, list_valid_slots).

-type action_type() :: challenge | verify_pin | decrypt_epw.
-type action() :: {challenge, slot_id()} | {verify_pin, pin()} |
    {decrypt_epw, slot_id(), epw()}.
-type action_result() :: ok | {ok, pw()}.

-spec transaction(fsm(), card_id(), [action()]) ->
    {ok, [action_result()]} | {error, action_type(), term()} | {error, term()}.
transaction(Pid, Card, Actions) ->
    gen_statem:call(Pid, {transaction, Card, Actions}).

-type slot_info() :: #{
    card_id => card_id(),
    slot_id => slot_id(),
    valid => boolean(),
    cert => #'OTPCertificate'{},
    pubkey => public_key:pubkey(),
    upn => [binary()],
    serial => integer(),
    dn => [#'AttributeTypeAndValue'{} | term()],
    cn => binary(),
    policies => [tuple()]
    }.

-type card_info() :: #{
    card_id => card_id(),
    reader => string(),
    yk_version => term(),
    yk_serial => integer(),
    slots => [slot_info()]
    }.

-type reader() :: string().
-type piv_pid() :: pid().

-record(card, {
    id :: card_id(),
    reader :: reader(),
    version :: integer(),
    chuid :: map(),
    scard :: undefined | rdpdr_scard:state(),
    apdu_stack = [] :: [{pid(), reference()}],
    piv :: undefined | piv_pid(),
    cak_valid :: undefined | boolean(),
    info = #{} :: card_info(),
    slots = [] :: [slot_id()]
    }).

-record(slot, {
    card_id :: card_id(),
    id :: nist_piv:slot_id(),
    piv :: piv_pid(),
    cert :: #'OTPCertificate'{},
    pubkey :: public_key:pubkey(),
    info = #{} :: slot_info()
    }).

-type url() :: string().

-record(?MODULE, {
    srv :: rdp_server:server(),
    fsm :: ui_fsm(),
    step_pid :: pid(),
    rdpdr :: undefined | pid(),
    scard :: undefined | rdpdr_scard:state(),
    rdrs = [] :: [reader()],
    cards = #{} :: #{card_id() => #card{}},
    slots = #{} :: #{{card_id(), slot_id()} => #slot{}},
    slots_todo = [],
    crl_cache = #{} :: #{url() => [{binary(), #'CertificateList'{}}]},
    ca_certs = [#'OTPCertificate'{}]
    }).

callback_mode() -> [state_functions, state_enter].

init([Srv, UiFsm]) ->
    {FPid, _} = Srv,
    lager:debug("scard_auth_fsm for ui_fsm ~p, frontend ~p", [UiFsm, FPid]),
    {ok, open_scard, #?MODULE{srv = Srv, fsm = UiFsm}}.

kill_card(#card{scard = SC0, apdu_stack = Stack}) ->
    ok = apdu_stack:stop(Stack),
    rdpdr_scard:disconnect(leave, SC0).

terminate(Reason, State, S0 = #?MODULE{cards = C0}) when map_size(C0) > 0 ->
    maps:foreach(fun (_Id, Card = #card{}) ->
        kill_card(Card)
    end, C0),
    terminate(Reason, State, S0#?MODULE{cards = #{}});
terminate(Reason, State, S0 = #?MODULE{scard = SC0}) when not (SC0 =:= undefined) ->
    rdpdr_scard:close(SC0),
    terminate(Reason, State, S0#?MODULE{scard = undefined});
terminate(Reason, State, #?MODULE{}) ->
    lager:debug("scard_auth_fsm going down from ~p: ~p", [State, Reason]),
    ok.

find_scard_devid(Devs) ->
    case lists:keyfind(rdpdr_dev_smartcard, 1, Devs) of
        false ->
            {error, no_scard};
        #rdpdr_dev_smartcard{id = DevId} ->
            {ok, DevId}
    end.

open_scard(enter, _PrevState, S0 = #?MODULE{srv = F}) ->
    Fsm = self(),
    {StepPid, _Ref} = spawn_monitor(fun() ->
        R = maybe
            {ok, RdpDr} ?= rdp_server:get_vchan_pid(F, rdpdr_fsm),
            {ok, Devs} ?= rdpdr_fsm:get_devices(RdpDr),
            {ok, DevId} ?= find_scard_devid(Devs),
            {ok, SC0} ?= rdpdr_scard:open(RdpDr, DevId, system),
            {ok, RdpDr, SC0}
        end,
        gen_statem:cast(Fsm, {result, R}),
        exit(normal)
    end),
    {keep_state, S0#?MODULE{step_pid = StepPid},
     [{state_timeout, 1000, abandon}]};
open_scard({call, _From}, _Msg, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};
open_scard(cast, stop, S0 = #?MODULE{step_pid = Pid}) ->
    exit(Pid, kill),
    receive
        {'DOWN', _, process, Pid, _} -> ok
    end,
    {stop, normal, S0};
open_scard(state_timeout, abandon, #?MODULE{step_pid = Pid}) ->
    exit(Pid, kill),
    keep_state_and_data;
open_scard(cast, {result, {ok, RdpDr, SC0}}, S0 = #?MODULE{step_pid = Pid}) ->
    S1 = S0#?MODULE{rdpdr = RdpDr, scard = SC0},
    receive
        {'DOWN', _, process, Pid, normal} -> ok
    end,
    {next_state, enum_cards, S1};
open_scard(info, {'DOWN', _, process, Pid, Why}, S0 = #?MODULE{step_pid = Pid}) ->
    lager:debug("failed to open scard device: ~p", [Why]),
    {next_state, no_scard, S0}.

try_list_groups(SC0) ->
    case rdpdr_scard:list_groups(SC0) of
        {ok, Groups, SC1} ->
            {ok, Groups ++ ["SCard$DefaultReaders", ""], SC1};
        _ ->
            {ok, ["SCard$DefaultReaders", ""], SC0}
    end.

try_list_readers([], SC0) ->
    {[], SC0};
try_list_readers([Group | Rest], SC0) ->
    case rdpdr_scard:list_readers(Group, SC0) of
        {ok, undefined, SC1} ->
            lager:debug("group ~s, readers undefined!", [Group]),
            try_list_readers(Rest, SC1);
        {ok, Readers, SC1} ->
            lager:debug("group ~s, readers = ~999p", [Group, Readers]),
            {RestReaders, SC2} = try_list_readers(Rest, SC1),
            {lists:usort(Readers ++ RestReaders), SC2};
        Err ->
            lager:debug("group ~s, err = ~999p", [Group, Err]),
            try_list_readers(Rest, SC0)
    end.

check_readers_for_cards([], SC0) ->
    {ok, [], SC0};
check_readers_for_cards([Reader | Rest], SC0) ->
    case rdpdr_scard:connect(Reader, shared, {t0_or_t1, optimal}, SC0) of
        {ok, Mode, SC1} ->
            {ok, Stack} = apdu_stack:start_link(element(1, Mode),
                [nist_piv, iso7816_chain, iso7816, {rdpdr_scard_apdu, [SC1]}]),
            [Piv | _] = Stack,

            R = maybe
                ok ?= apdu_transform:begin_transaction(Piv),
                {ok, [{ok, #{version := Version}}]} ?=
                    apdu_transform:command(Piv, select),
                {ok, [{ok, Chuid = #{guid := Guid}}]} ?=
                    apdu_transform:command(Piv, read_chuid),
                lager:debug("PIV applet v~B in ~p, GUID ~s", [Version, Reader,
                    binary:encode_hex(Guid)]),
                I0 = case apdu_transform:command(Piv, yk_get_version) of
                    {ok, [{ok, YkVersion}]} ->
                        #{yk_version => YkVersion};
                    _ -> #{}
                end,
                I1 = case apdu_transform:command(Piv, yk_get_serial) of
                    {ok, [{ok, Serial}]} ->
                        I0#{yk_serial => Serial};
                    _ -> #{}
                end,
                I2 = I1#{reader => Reader},
                {ok, #card{id = Guid, reader = Reader,
                           version = Version, chuid = Chuid,
                           info = I2}}
            end,
            apdu_transform:end_transaction(Piv),
            ok = apdu_stack:stop(Stack),
            {ok, SC2} = rdpdr_scard:disconnect(leave, SC1),

            case R of
                {ok, Card} ->
                    {ok, RestCards, SC3} = check_readers_for_cards(Rest, SC2),
                    {ok, [Card | RestCards], SC3};
                _ ->
                    check_readers_for_cards(Rest, SC2)
            end;
        _ ->
            check_readers_for_cards(Rest, SC0)
    end.

enum_cards(enter, _PrevState, S0 = #?MODULE{scard = SC0, cards = OldCards}) ->
    maps:foreach(fun (_Id, Card = #card{}) ->
        kill_card(Card)
    end, OldCards),
    S1 = S0#?MODULE{cards = #{}, rdrs = [], slots = #{}},
    Fsm = self(),
    {StepPid, _Ref} = spawn_monitor(fun() ->
        R = maybe
            {ok, Groups, SC1} ?= try_list_groups(SC0),
            {Readers, SC2} ?= try_list_readers(Groups, SC1),
            {ok, Cards, SC3} ?= check_readers_for_cards(Readers, SC2),
            {ok, Readers, Cards, SC3}
        end,
        gen_statem:cast(Fsm, {result, R}),
        exit(normal)
    end),
    {keep_state, S1#?MODULE{step_pid = StepPid},
     [{state_timeout, 5000, abandon}]};
enum_cards({call, _From}, _Msg, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};
enum_cards(state_timeout, abandon, #?MODULE{step_pid = Pid}) ->
    exit(Pid, kill),
    keep_state_and_data;
enum_cards(cast, stop, S0 = #?MODULE{step_pid = Pid}) ->
    exit(Pid, kill),
    receive
        {'DOWN', _, process, Pid, _} -> ok
    end,
    {stop, normal, S0};
enum_cards(cast, {result, {ok, Readers, Cards, SC0}}, S0 = #?MODULE{step_pid = Pid}) ->
    CardMap = lists:foldl(fun (C0 = #card{id = Guid, reader = Rdr}, Acc0) ->
        R = maybe
            {ok, Mode, SC1} ?= rdpdr_scard:connect(Rdr, shared,
                {t0_or_t1, optimal}, SC0),
            {ok, Stack} ?= apdu_stack:start_monitor(element(1, Mode),
                [nist_piv, iso7816_chain, iso7816, {rdpdr_scard_apdu, [SC1]}]),
            [{Piv, _} | _] = Stack,
            C1 = C0#card{scard = SC1, apdu_stack = Stack, piv = Piv},
            {ok, Acc0#{Guid => C1}}
        end,
        case R of
            {ok, Acc1} ->
                Acc1;
            Err ->
                lager:debug("dropping card ~p (~p): ~p", [Guid, Rdr, Err]),
                Acc0
        end
    end, #{}, Cards),
    S1 = S0#?MODULE{rdrs = Readers, cards = CardMap, scard = SC0},
    receive
        {'DOWN', _, process, Pid, normal} -> ok
    end,
    case maps:size(CardMap) of
        0 ->
            lager:debug("no workable cards found"),
            {next_state, no_cards, S1};
        _ ->
            {next_state, enum_slots, S1}
    end;
enum_cards(info, {'DOWN', _, process, Pid, Why}, S0 = #?MODULE{step_pid = Pid}) ->
    lager:debug("failed to enumerate cards: ~p", [Why]),
    {next_state, no_scard, S0}.

check_slots_on_card(Card, SlotIds) ->
    #card{id = CardId, piv = Piv} = Card,
    R = maybe
        ok ?= apdu_transform:begin_transaction(Piv),
        {ok, [{ok, _}]} ?= apdu_transform:command(Piv, select),
        {ok, lists:foldl(fun (SlotId, Acc) ->
            SR = maybe
                {ok, Cert} ?= card_cmd(Card, {read_cert, SlotId}),
                {ok, PubKey} ?= cert_to_pubkey(Cert),
                Slot = #slot{card_id = CardId, id = SlotId,
                             piv = Piv, cert = Cert, pubkey = PubKey},
                {ok, Acc#{{CardId, SlotId} => Slot}}
            end,
            case SR of
                {ok, Acc1} ->
                    Acc1;
                Why ->
                    lager:debug("failed to read cert ~p / ~p: ~p",
                        [CardId, SlotId, Why]),
                    Acc
            end
        end, #{}, SlotIds)}
    end,
    apdu_transform:end_transaction(Piv),
    case R of
        {ok, Slots} -> {ok, Slots};
        Why ->
            lager:debug("failed to enum ~p: ~p", [CardId, Why]),
            {error, enum_failed}
    end.

enum_slots(enter, _PrevState, S0 = #?MODULE{cards = Cards0}) ->
    S1 = S0#?MODULE{slots = #{}},
    SCardConfig = application:get_env(rdpproxy, smartcard, []),
    EnumSlots = proplists:get_value(enum_slots, SCardConfig,
        [piv_card_auth, piv_auth, piv_key_mgmt]),
    Fsm = self(),
    {StepPid, _Ref} = spawn_monitor(fun() ->
        {Cards1, Slots} = lists:foldl(fun (Card0, {CardsAcc, SlotsAcc}) ->
            #card{id = CardId} = Card0,
            case check_slots_on_card(Card0, EnumSlots) of
                {ok, CardSlots} ->
                    Card1 = Card0#card{
                        slots = [SlotId || {_, SlotId} <- maps:keys(CardSlots)] },
                    {CardsAcc#{CardId => Card1},
                     maps:merge(CardSlots, SlotsAcc)};
                _ ->
                    {CardsAcc, SlotsAcc}
            end
        end, {Cards0, #{}}, maps:values(Cards0)),
        gen_statem:cast(Fsm, {result, {ok, Cards1, Slots}}),
        exit(normal)
    end),
    {keep_state, S1#?MODULE{step_pid = StepPid},
     [{state_timeout, 5000, abandon}]};
enum_slots({call, _From}, _Msg, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};
enum_slots(state_timeout, abandon, #?MODULE{step_pid = Pid}) ->
    exit(Pid, kill),
    keep_state_and_data;
enum_slots(cast, stop, S0 = #?MODULE{step_pid = Pid}) ->
    exit(Pid, kill),
    receive
        {'DOWN', _, process, Pid, _} -> ok
    end,
    {stop, normal, S0};
enum_slots(cast, {result, {ok, Cards, Slots}}, S0 = #?MODULE{step_pid = Pid}) ->
    S1 = S0#?MODULE{cards = Cards, slots = Slots},
    receive
        {'DOWN', _, process, Pid, normal} -> ok
    end,
    case maps:size(Slots) of
        0 ->
            lager:debug("no usable slots found"),
            {next_state, no_cards, S1};
        _ ->
            {next_state, validate_certs, S1}
    end;
enum_slots(info, {'DOWN', _, process, Pid, Why}, S0 = #?MODULE{step_pid = Pid}) ->
    lager:debug("failed to enumerate slots: ~p", [Why]),
    {next_state, no_scard, S0};
enum_slots(info, {'DOWN', _, process, Pid, Why}, S0 = #?MODULE{cards = Cards0}) ->
    C = lists:search(fun (#card{apdu_stack = Stack}) ->
        lists:any(fun
            ({APid, _Ref}) when APid =:= Pid -> true;
            (_) -> false
        end, Stack)
    end, maps:values(Cards0)),
    Cards1 = case C of
        {value, Card = #card{id = Guid}} ->
            lager:debug("pid ~p from apdu stack of card ~p died: ~p",
                [Pid, Guid, Why]),
            (catch kill_card(Card)),
            maps:remove(Guid, Cards0);
        false ->
            lager:debug("got unknown down message about pid ~p: ~p", [Pid, Why]),
            Cards0
    end,
    {keep_state, S0#?MODULE{cards = Cards1}}.

validate_certs(enter, _PrevState, S0 = #?MODULE{slots = Slots}) ->
    SCardConfig = application:get_env(rdpproxy, smartcard, []),

    CACertPath = proplists:get_value(ca_cert, SCardConfig,
        "/etc/ssl/cert.pem"),
    {ok, CAData} = file:read_file(CACertPath),
    Entries0 = public_key:pem_decode(CAData),
    Entries1 = [public_key:pkix_decode_cert(E, otp) || {'Certificate',E,_} <- Entries0],

    S1 = S0#?MODULE{slots_todo = maps:keys(Slots),
                    ca_certs = Entries1},

    {keep_state, S1, [{state_timeout, 0, next_slot}]};
validate_certs({call, _From}, _Msg, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};
validate_certs(state_timeout, next_slot, S0 = #?MODULE{slots_todo = []}) ->
    {next_state, ready, S0};
validate_certs(state_timeout, next_slot, S0 = #?MODULE{slots_todo = [Key | Rest],
                                                       slots = SL0,
                                                       cards = C0,
                                                       ca_certs = CACerts,
                                                       crl_cache = CRL0}) ->
    {CardId, SlotId} = Key,
    #{Key := Slot0} = SL0,
    #{CardId := Card0} = C0,

    #slot{cert = Cert} = Slot0,

    DPs = public_key:pkix_dist_points(Cert),
    {ok, DPandCRLs, CRL1} = fetch_dps(DPs, CRL0),

    CRLOpts = [
        {issuer_fun, {fun (_DP, CL, _Name, none) ->
            {ok, CLCA} = find_ca(CACerts, CL),
            {ok, CLCA, []}
        end, none}}
    ],

    SCardConfig = application:get_env(rdpproxy, smartcard, []),
    CNTrustPol = proplists:get_value(cn_upn_policy_id, SCardConfig, false),

    #'OTPCertificate'{tbsCertificate = TBS} = Cert,
    #'OTPTBSCertificate'{extensions = Exts,
                         subject = {rdnSequence, Subj},
                         serialNumber = Serial} = TBS,
    SANExts = [E || E = #'Extension'{extnID = ID} <- Exts,
               ID =:= ?'id-ce-subjectAltName'],
    SI1 = case SANExts of
        [#'Extension'{extnValue = SANs}] ->
            Ders = [V || {otherName, {'INSTANCE OF', ?'szOID_NT_PRINCIPAL_NAME', V}} <- SANs],
            Tlvs = [asn1rt_nif:decode_ber_tlv(Der) || Der <- Ders],
            UPNs = [Str || {{_Tag, Str}, <<>>} <- Tlvs, is_binary(Str)],
            #{upn => UPNs};
        _ ->
            #{}
    end,
    SI2 = SI1#{serial => Serial, dn => Subj},
    SI3 = case get_dn_attr(Subj, ?'id-at-commonName') of
        false -> SI2;
        {_Type, CN} -> SI2#{cn => CN};
        CN -> SI2#{cn => CN}
    end,
    PolExts = [E || E  = #'Extension'{extnID = ID} <- Exts,
                    ID =:= ?'id-ce-certificatePolicies'],
    SI4 = case PolExts of
        [#'Extension'{extnValue = PolInfos}] ->
            Pols = [Oid || #'PolicyInformation'{policyIdentifier = Oid} <- PolInfos],
            SI3#{policies => Pols};
        _ ->
            SI3
    end,
    SI5 = case lists:member(CNTrustPol, maps:get(policies, SI4, [])) of
        true ->
            UPN0 = maps:get(upn, SI4, []),
            TrustedCN = maps:get(cn, SI4),
            case re:run(TrustedCN, "^[a-zA-Z][a-zA-Z0-9_-]+(@[a-zA-Z0-9._-]+)?$") of
                nomatch ->
                    % doesn't look like a valid upn in there, ignore it
                    SI4;
                _ ->
                    SI4#{upn => [TrustedCN | UPN0]}
            end;
        false ->
            SI4
    end,

    R = maybe
        {ok, CA} ?= find_ca(CACerts, Cert),
        {ok, _} ?= public_key:pkix_path_validation(CA, [Cert], []),
        valid ?= public_key:pkix_crls_validate(Cert, DPandCRLs, CRLOpts),
        {ok, valid}
    end,
    Slot1 = case R of
        {ok, valid} ->
            Slot0#slot{info = SI5#{valid => true}};
        {error, {unknown_ca, _}} ->
            Slot0#slot{info = SI5#{valid => false}};
        {error, {bad_cert, cert_expired}} ->
            Slot0#slot{info = SI5#{valid => true}};
        {error, Why} ->
            lager:debug("cert in ~s slot ~p failed verification: ~p",
                [binary:encode_hex(CardId), SlotId, Why]),
            Slot0#slot{info = SI5#{valid => false}}
    end,
    Card1 = case SlotId of
        piv_card_auth ->
            Card0#card{cak_valid = maps:get(valid, Slot1#slot.info, false)};
        _ ->
            Card0
    end,

    S1 = S0#?MODULE{slots_todo = Rest,
                    slots = SL0#{Key => Slot1},
                    cards = C0#{CardId => Card1},
                    crl_cache = CRL1},

    {keep_state, S1, [{state_timeout, 0, next_slot}]};

validate_certs(cast, stop, S0 = #?MODULE{}) ->
    {stop, normal, S0};
validate_certs(info, {'DOWN', _, process, Pid, Why},
               S0 = #?MODULE{cards = Cards0, slots = Slots0,
                             slots_todo = Todo0}) ->
    C = lists:search(fun (#card{apdu_stack = Stack}) ->
        lists:any(fun
            ({APid, _Ref}) when APid =:= Pid -> true;
            (_) -> false
        end, Stack)
    end, maps:values(Cards0)),
    S1 = case C of
        {value, Card = #card{id = Guid, slots = CardSlots}} ->
            lager:debug("pid ~p from apdu stack of card ~p died: ~p",
                [Pid, Guid, Why]),
            (catch kill_card(Card)),
            Cards1 = maps:remove(Guid, Cards0),
            Slots1 = lists:foldl(fun (SlotId) ->
                maps:remove({Guid, SlotId}, Slots0)
            end, Slots0, CardSlots),
            Todo1 = lists:filter(fun
                ({Id, _SlotId}) when (Guid =:= Id) -> false;
                (_) -> true
            end, Todo0),
            S0#?MODULE{cards = Cards1, slots = Slots1, slots_todo = Todo1};
        false ->
            lager:debug("got unknown down message about pid ~p: ~p", [Pid, Why]),
            S0
    end,
    {keep_state, S1}.

no_scard(enter, _PrevState, #?MODULE{}) ->
    {keep_state_and_data, [{state_timeout, 1000, refresh}]};
no_scard(state_timeout, refresh, S0 = #?MODULE{}) ->
    {next_state, open_scard, S0};
no_scard(cast, stop, S0 = #?MODULE{}) ->
    {stop, normal, S0};
no_scard({call, From}, list_cards, #?MODULE{}) ->
    {keep_state_and_data, [{reply, From, {error, scard_not_available}}]};
no_scard({call, From}, _, #?MODULE{}) ->
    {keep_state_and_data, [{reply, From, {error, scard_not_available}}]}.

no_cards(enter, _PrevState, #?MODULE{}) ->
    {keep_state_and_data, [{state_timeout, 1000, refresh}]};
no_cards(state_timeout, refresh, S0 = #?MODULE{}) ->
    {next_state, enum_cards, S0};
no_cards(cast, stop, S0 = #?MODULE{}) ->
    {stop, normal, S0};
no_cards({call, From}, list_cards, #?MODULE{}) ->
    {keep_state_and_data, [{reply, From, {ok, []}}]};
no_cards({call, From}, _, #?MODULE{}) ->
    {keep_state_and_data, [{reply, From, {error, no_cards}}]}.

ready(enter, _PrevState, #?MODULE{fsm = Fsm}) ->
    Fsm ! {scard_ready, self()},
    keep_state_and_data;
ready({call, From}, list_cards, #?MODULE{cards = C0, slots = SL0}) ->
    CIs = maps:fold(fun (CardId, Card, CAcc) ->
        #card{slots = SlotIds, info = CI0} = Card,
        SIs = lists:foldl(fun (SlotId, SAcc) ->
            #{{CardId, SlotId} := Slot} = SL0,
            #slot{pubkey = PubKey, cert = Cert, info = SI0} = Slot,
            SI1 = SI0#{card_id => CardId, slot_id => SlotId,
                       cert => Cert, pubkey => PubKey},
            [SI1 | SAcc]
        end, [], SlotIds),
        CI1 = CI0#{card_id => CardId, slots => SIs},
        [CI1 | CAcc]
    end, [], C0),
    {keep_state_and_data, [{reply, From, {ok, CIs}}]};
ready({call, From}, {get_card, CardId}, S0 = #?MODULE{slots = SL0}) ->
    R = maybe
        {ok, #card{slots = SlotIds, info = CI0}} ?= find_card(CardId, S0),
        SIs = lists:foldl(fun (SlotId, SAcc) ->
            #{{CardId, SlotId} := Slot} = SL0,
            #slot{pubkey = PubKey, cert = Cert, info = SI0} = Slot,
            SI1 = SI0#{card_id => CardId, slot_id => SlotId,
                       cert => Cert, pubkey => PubKey},
            [SI1 | SAcc]
        end, [], SlotIds),
        CI1 = CI0#{card_id => CardId, slots => SIs},
        {ok, CI1}
    end,
    {keep_state_and_data, [{reply, From, R}]};
ready({call, From}, {get_slot, CardId, SlotId}, S0 = #?MODULE{}) ->
    R = maybe
        {ok, #card{info = CI0}} ?= find_card(CardId, S0),
        {ok, #slot{pubkey = PubKey, cert = Cert, info = SI0}} ?= find_slot(CardId, SlotId, S0),
        SI1 = SI0#{card_id => CardId, slot_id => SlotId,
                   cert => Cert, pubkey => PubKey},
        CI1 = CI0#{card_id => CardId},
        {ok, CI1, SI1}
    end,
    {keep_state_and_data, [{reply, From, R}]};
ready({call, From}, list_valid_slots, #?MODULE{cards = C0, slots = SL0}) ->
    CSIs = maps:fold(fun
        (CardId, Card = #card{cak_valid = true}, CAcc) ->
            #card{slots = SlotIds} = Card,
            lists:foldl(fun (SlotId, SAcc) ->
                #{{CardId, SlotId} := Slot} = SL0,
                case Slot of
                    #slot{info = SI0 = #{valid := true},
                          pubkey = PubKey, cert = Cert} ->
                        SI1 = SI0#{card_id => CardId, slot_id => SlotId,
                                   cert => Cert, pubkey => PubKey},
                        [SI1 | SAcc];
                    _ ->
                        SAcc
                end
            end, CAcc, SlotIds);
        (_, _, CAcc) ->
            CAcc
    end, [], C0),
    {keep_state_and_data, [{reply, From, {ok, CSIs}}]};
ready({call, From}, {transaction, CardId, Actions}, S0 = #?MODULE{}) ->
    R = maybe
        {ok, Card} ?= find_card(CardId, S0),
        #card{piv = Piv} = Card,
        ok ?= apdu_transform:begin_transaction(Piv),
        RR = do_card_actions(Card, S0, Actions),
        apdu_transform:end_transaction(Piv),
        RR
    end,
    {keep_state_and_data, [{reply, From, R}]};
ready(cast, stop, S0 = #?MODULE{}) ->
    {stop, normal, S0};
ready(info, {'DOWN', _, process, Pid, Why},
      S0 = #?MODULE{cards = Cards0, slots = Slots0,
                    slots_todo = Todo0}) ->
    C = lists:search(fun (#card{apdu_stack = Stack}) ->
        lists:any(fun
            ({APid, _Ref}) when APid =:= Pid -> true;
            (_) -> false
        end, Stack)
    end, maps:values(Cards0)),
    S1 = case C of
        {value, Card = #card{id = Guid, slots = CardSlots}} ->
            lager:debug("pid ~p from apdu stack of card ~p died: ~p",
                [Pid, Guid, Why]),
            (catch kill_card(Card)),
            Cards1 = maps:remove(Guid, Cards0),
            Slots1 = lists:foldl(fun (SlotId) ->
                maps:remove({Guid, SlotId}, Slots0)
            end, Slots0, CardSlots),
            Todo1 = lists:filter(fun
                ({Id, _SlotId}) when (Guid =:= Id) -> false;
                (_) -> true
            end, Todo0),
            S0#?MODULE{cards = Cards1, slots = Slots1, slots_todo = Todo1};
        false ->
            lager:debug("got unknown down message about pid ~p: ~p", [Pid, Why]),
            S0
    end,
    {keep_state, S1}.

find_card(CardId, #?MODULE{cards = C0}) ->
    case C0 of
        #{CardId := Card} -> {ok, Card};
        _ -> {error, card_not_found}
    end.

find_slot(CardId, SlotId, #?MODULE{slots = S0}) ->
    case S0 of
        #{{CardId, SlotId} := Slot} -> {ok, Slot};
        _ -> {error, slot_not_found}
    end.

do_card_actions(C = #card{id = CardId}, S0 = #?MODULE{slots = SL0},
                [{challenge, SlotId} | Rest]) ->
    #slot{pubkey = PubKey} = maps:get({CardId, SlotId}, SL0),
    err_step(challenge, maybe
        ok ?= challenge_key(C, SlotId, PubKey),
        {ok, RestResults} ?= do_card_actions(C, S0, Rest),
        {ok, [ok | RestResults]}
    end);

do_card_actions(#card{cak_valid = false}, #?MODULE{}, [{verify_pin, _} | _Rest]) ->
    {error, verify_pin, no_valid_cak};
do_card_actions(C = #card{id = CardId}, S0 = #?MODULE{}, [{verify_pin, Pin} | Rest]) ->
    err_step(verify_pin, maybe
        {ok, #slot{pubkey = PubKey}} ?= find_slot(CardId, piv_card_auth, S0),
        ok ?= challenge_key(C, piv_card_auth, PubKey),
        ok ?= card_cmd(C, {verify_pin, piv_pin, Pin}),
        {ok, RestResults} ?= do_card_actions(C, S0, Rest),
        {ok, [ok | RestResults]}
    end);

do_card_actions(C = #card{piv = Piv, id = CardId}, S0 = #?MODULE{},
                [{decrypt_epw, SlotId, Epw} | Rest]) ->
    err_step(decrypt_epw, maybe
        {ok, #slot{}} ?= find_slot(CardId, SlotId, S0),
        {ok, Pw} ?= scard_saved_pw_ra:decrypt(Epw, Piv, SlotId),
        {ok, RestResults} ?= do_card_actions(C, S0, Rest),
        {ok, [{ok, Pw} | RestResults]}
    end);

do_card_actions(#card{}, #?MODULE{}, []) -> {ok, []}.

card_cmd(#card{piv = Piv}, Cmd) ->
    case apdu_transform:command(Piv, Cmd) of
        {ok, [Result]} -> Result;
        {error, Why} -> {error, Why}
    end.

algo_for_key(PubKey) ->
    case (catch nist_piv:algo_for_key(PubKey)) of
        {'EXIT', Why} -> {error, {bad_pubkey_algo, Why}};
        Algo -> {ok, Algo}
    end.

bool_to_err(_Err, true) -> ok;
bool_to_err(Err, false) -> {error, Err}.

err_step(Step, {error, Why}) -> {error, Step, Why};
err_step(Step, T) when is_tuple(T) and element(1, T) =:= error ->
    [error | Rest] = tuple_to_list(T),
    {error, Step, list_to_tuple(Rest)};
err_step(_Step, Other) -> Other.

hash_for_algo(rsa1024) -> {ok, sha256};
hash_for_algo(rsa2048) -> {ok, sha512};
hash_for_algo(eccp256) -> {ok, sha256};
hash_for_algo(eccp384) -> {ok, sha384};
hash_for_algo(eccp521) -> {ok, sha512};
hash_for_algo(Other) -> {error, {no_hash_for_algo, Other}}.

make_sign_blob(PubKey, Alg, Data) ->
    maybe
        {ok, HashAlg} ?= hash_for_algo(Alg),
        Hash = crypto:hash(HashAlg, Data),
        case Alg of
            rsa1024 -> maybe
                {ok, Info} ?= 'PKCS7':encode('DigestInfo', #'DigestInfo'{
                    digestAlgorithm = #'PKCS7AlgorithmIdentifier'{
                        algorithm = ?'id-sha256',
                        parameters = <<5,0>>},
                    digest = Hash}),
                PadLen = (1024 div 8) - byte_size(Info) - 3,
                Pad = binary:copy(<<16#FF>>, PadLen),
                {ok, HashAlg, <<16#00, 16#01, Pad/binary, 16#00, Info/binary>>}
            end;
            rsa2048 -> maybe
                {ok, Info} ?= 'PKCS7':encode('DigestInfo', #'DigestInfo'{
                    digestAlgorithm = #'PKCS7AlgorithmIdentifier'{
                        algorithm = ?'id-sha512',
                        parameters = <<5,0>>},
                    digest = Hash}),
                PadLen = (2048 div 8) - byte_size(Info) - 3,
                Pad = binary:copy(<<16#FF>>, PadLen),
                {ok, HashAlg, <<16#00, 16#01, Pad/binary, 16#00, Info/binary>>}
            end;
            _ ->
                {ok, HashAlg, Hash}
        end
    end.

challenge_key(Card, Slot, PubKey) ->
    maybe
        {ok, Alg} ?= algo_for_key(PubKey),
        Challenge = <<"rdpproxy challenge", 0,
            (crypto:strong_rand_bytes(16))/binary>>,
        {ok, HashAlg, Input} ?= make_sign_blob(PubKey, Alg, Challenge),
        {ok, CardSig} ?= card_cmd(Card, {sign, Slot, Alg, Input}),
        ok ?= bool_to_err(verification_failed,
            public_key:verify(Challenge, HashAlg, CardSig, PubKey)),
        ok
    end.

get_dn_attr([], _Attr) ->
    false;
get_dn_attr([#'AttributeTypeAndValue'{type = Attr, value = V} | _], Attr) ->
    V;
get_dn_attr([L | Rest], Attr) when is_list(L) ->
    case get_dn_attr(L, Attr) of
        false -> get_dn_attr(Rest, Attr);
        Other -> Other
    end;
get_dn_attr([_ | Rest], Attr) ->
    get_dn_attr(Rest, Attr).

find_ca([], #'OTPCertificate'{tbsCertificate = TBS}) ->
    #'OTPTBSCertificate'{issuer = {rdnSequence, Issuer}} = TBS,
    {error, {unknown_ca, Issuer}};
find_ca([], _Cert) ->
    {error, unknown_ca};
find_ca([CA | Rest], Cert) ->
    case public_key:pkix_is_issuer(Cert, CA) of
        true -> {ok, CA};
        false -> find_ca(Rest, Cert)
    end.

parse_crl_body(Body) ->
    case (catch public_key:der_decode('CertificateList', Body)) of
        {'EXIT', _} ->
            case (catch public_key:pem_decode(Body)) of
                {'EXIT', Why} -> {error, Why};
                [] -> {error, empty};
                CLs ->
                    {ok, [{D, public_key:der_decode('CertificateList', D)}
                          || {'CertificateList', D, not_encrypted} <- CLs]}
            end;
        CL = #'CertificateList'{} ->
            {ok, [{Body, CL}]}
    end.

fetch_dps([DP = #'DistributionPoint'{distributionPoint = {fullName, Names}} | Rest], Cache0) ->
    {ok, FromThisDP, Cache1} = fetch_dp_names(DP, Names, Cache0),
    {ok, FromRest, Cache2} = fetch_dps(Rest, Cache1),
    {ok, FromThisDP ++ FromRest, Cache2};
fetch_dps([], Cache) -> {ok, [], Cache}.

fetch_dp_names(DP, [{uniformResourceIdentifier, "http"++_ = URL} | Rest], Cache0) ->
    R = case Cache0 of
        #{URL := List} ->
            {ok, List, Cache0};
        _ ->
            maybe
                {ok, {_Status, _Hdrs, Body}} ?= httpc:request(get,
                    {URL, [{"connection", "close"}]},
                    [{timeout, 1000}],
                    [{body_format, binary}]),
                {ok, List} ?= parse_crl_body(Body),
                {ok, List, Cache0#{URL => List}}
            end
    end,
    case R of
        {ok, CLs, Cache1} ->
            FromThisName = [{DP, X} || X <- CLs],
            {ok, FromOtherNames, Cache2} = fetch_dp_names(DP, Rest, Cache1),
            {ok, FromThisName ++ FromOtherNames, Cache2};
        _ ->
            fetch_dp_names(DP, Rest, Cache0)
    end;
fetch_dp_names(_DP, [], Cache) -> {ok, [], Cache}.

cert_to_pubkey(#'OTPCertificate'{} = Cert) ->
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{subjectPublicKeyInfo = SPKI}
        } = Cert,
    #'OTPSubjectPublicKeyInfo'{
        algorithm = #'PublicKeyAlgorithm'{
            algorithm = AlgoOID,
            parameters = Params},
        subjectPublicKey = PubKey} = SPKI,
    case AlgoOID of
        ?'rsaEncryption' ->
            {ok, PubKey};
        ?'id-ecPublicKey' ->
            {namedCurve, CurveOID} = Params,
            case CurveOID of
                A when is_atom(A) ->
                    {ok, {PubKey, {namedCurve, CurveOID}}};
                ?'secp256r1' ->
                    {ok, {PubKey, {namedCurve, secp256r1}}};
                ?'secp521r1' ->
                    {ok, {PubKey, {namedCurve, secp521r1}}};
                _ ->
                    {error, unknown_curve}
            end;
        _ ->
            {error, unknown_algorithm}
    end.
