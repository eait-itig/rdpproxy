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

config_to_krb_client_opts(Config, CC) ->
    maps:filter(fun
        (kdc, _) -> true;
        (ciphers, _) -> true;
        (timeout, _) -> true;
        (cc, _) -> true;
        (_, _) -> false
    end, Config#{cc => CC}).

check_service(C, Realm, User, SPN, KeyMap, NeedPac) ->
    case krb_client:obtain_ticket(C, SPN) of
        {ok, _Key, Ticket} ->
            #'Ticket'{'enc-part' = EPart} = Ticket,
            EType = krb_crypto:etype_to_atom(EPart#'EncryptedData'.etype),
            case KeyMap of
                #{EType := Key} ->
                    Data = krb_crypto:decrypt(EType, Key,
                        EPart#'EncryptedData'.cipher, #{usage => 2}),
                    {ok, Inner, <<>>} = 'KRB5':decode('EncTicketPart', Data),
                    #'EncTicketPart'{cname = CName} = Inner,
                    UserBin = iolist_to_binary([User]),
                    UserString = unicode:characters_to_list(UserBin, latin1),
                    #'PrincipalName'{'name-string' = [UserString]} = CName,
                    ADs = Inner#'EncTicketPart'.'authorization-data',
                    Pacs = case ADs of
                        asn1_NOVALUE -> [];
                        [_ | _] ->
                            lists:filter(fun
                                (#'AuthorizationData_SEQOF'{'ad-type' = 1}) -> true;
                                (_) -> false
                            end, ADs)
                    end,
                    HasPac = (length(Pacs) > 0),
                    case {NeedPac, HasPac} of
                        {true, false} ->
                            lager:debug("no PAC found in ticket for ~p (~p@~p)",
                                [User, SPN, Realm]),
                            false;
                        _ -> true
                    end;
                _ ->
                    lager:debug("no key available for ~p@~p etype ~p",
                        [SPN, Realm, EType]),
                    false
            end;
        Other ->
            lager:debug("failed to obtain service ticket for ~p as ~p in ~p: ~p",
                [SPN, User, Realm, Other]),
            false
    end.

authenticate(#{username := U, password := P}) ->
    Krb5Config = maps:from_list(application:get_env(rdpproxy, krb5, [])),

    {ok, CC} = krbcc:start_link(krbcc_ets, #{}),

    Opts = config_to_krb_client_opts(Krb5Config, CC),
    #{realm := AuthRealm} = Krb5Config,
    {ok, C0} = krb_client:open(AuthRealm, Opts),

    Res = case krb_client:authenticate(C0, U, P) of
        ok ->
            Res2 = case Krb5Config of
                #{service := SPN, service_keys := KeyList} ->
                    KeyMap = maps:from_list(KeyList),
                    NeedPac = maps:get(require_pac, Krb5Config, false),
                    check_service(C0, AuthRealm, U, SPN, KeyMap, NeedPac);
                _ -> true
            end,
            Res3 = case Krb5Config of
                #{cross_realm := XRealmConfLists} ->
                    lists:all(fun (XRealmConfList) ->
                        XRealmConf = maps:from_list(XRealmConfList),
                        #{realm := XRealm} = XRealmConf,
                        {ok, _, _} = krb_client:obtain_ticket(C0, ["krbtgt", XRealm]),
                        XOpts = config_to_krb_client_opts(XRealmConf, CC),
                        {ok, CX} = krb_client:open(XRealm, XOpts),
                        XRes = case XRealmConf of
                            #{service := XSPN, service_keys := XKeyList} ->
                                XKeyMap = maps:from_list(XKeyList),
                                XNeedPac = maps:get(require_pac, XRealmConf, false),
                                check_service(CX, XRealm, U, XSPN, XKeyMap, XNeedPac);
                            _ -> true
                        end,
                        krb_client:close(CX),
                        XRes
                    end, XRealmConfLists);
                _ -> true
            end,
            Res2 and Res3;
        _ -> false
    end,
    krb_client:close(C0),
    krbcc:stop(CC),
    Res.
