%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2022 Alex Wilson <alex@uq.edu.au>
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

-module(scard_auth).

-include_lib("public_key/include/public_key.hrl").

-export([
    check/1
    ]).

check(SC0) ->
    case rdpdr_scard:list_groups(SC0) of
        {ok, [Group0 | _], SC1} ->
            {ok, Readers, SC2} = rdpdr_scard:list_readers(Group0, SC1),
            check_rdr(Readers, SC2);
        _ ->
            case rdpdr_scard:list_readers("SCard$DefaultReaders", SC0) of
                {ok, Readers, SC1} ->
                    check_rdr(Readers, SC1);
                _ ->
                    {ok, Readers, SC1} = rdpdr_scard:list_readers("", SC0),
                    check_rdr(Readers, SC1)
            end
    end.

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
            PubKey;
        ?'id-ecPublicKey' ->
            {namedCurve, CurveOID} = Params,
            case CurveOID of
                A when is_atom(A) -> {PubKey, {namedCurve, CurveOID}};
                ?'secp256r1' -> {PubKey, {namedCurve, secp256r1}};
                ?'secp384r1' -> {PubKey, {namedCurve, secp384r1}}
            end
    end.

alg_for_key(#'RSAPublicKey'{modulus = M}) ->
    case bit_size(binary:encode_unsigned(M)) of
        S when S =< 1024 -> rsa1024;
        S when S =< 2048 -> rsa2048
    end;
alg_for_key({#'ECPoint'{}, {namedCurve, prime256v1}}) ->
    eccp256;
alg_for_key({#'ECPoint'{}, {namedCurve, secp256r1}}) ->
    eccp256;
alg_for_key({#'ECPoint'{}, {namedCurve, secp384r1}}) ->
    eccp384;
alg_for_key(#'ECPoint'{point = <<4, _/binary>> = P}) when bit_size(P) =< 520 ->
    eccp256;
alg_for_key(#'ECPoint'{point = <<4, _/binary>> = P}) when bit_size(P) =< 776 ->
    eccp384.

fetch_dp_and_crls(Cert) ->
    DPs = public_key:pkix_dist_points(Cert),
    fetch_dps(DPs).

fetch_dps([DP = #'DistributionPoint'{distributionPoint = {fullName, Names}} | Rest]) ->
    fetch_dp_names(DP, Names) ++ fetch_dps(Rest);
fetch_dps([_ | Rest]) ->
    fetch_dps(Rest);
fetch_dps([]) -> [].

fetch_dp_names(DP, [{uniformResourceIdentifier, "http"++_ = URL} | Rest]) ->
    case httpc:request(get, {URL, [{"connection", "close"}]},
                       [{timeout, 1000}], [{body_format, binary}]) of
        {ok, {_Status, _Headers, Body}} ->
            case (catch public_key:der_decode('CertificateList', Body)) of
                {'EXIT', _} ->
                    case (catch public_key:pem_decode(Body)) of
                        {'EXIT', _} -> fetch_dp_names(DP, Rest);
                        [] -> fetch_dp_names(DP, Rest);
                        CLs ->
                            [{DP, {D, public_key:der_decode('CertificateList', D)},
                                  {D, public_key:der_decode('CertificateList', D)}}
                             || {'CertificateList', D, not_encrypted} <- CLs]
                            ++ fetch_dp_names(DP, Rest)
                    end;
                CL = #'CertificateList'{} ->
                    [{DP, {Body, CL}, {Body, CL}} | fetch_dp_names(DP, Rest)]
            end;
        _ ->
            fetch_dp_names(DP, Rest)
    end;
fetch_dp_names(DP, [_ | Rest]) ->
    fetch_dp_names(DP, Rest);
fetch_dp_names(_DP, []) -> [].

find_ca([], Cert = #'OTPCertificate'{tbsCertificate = TBS}) ->
    #'OTPTBSCertificate'{issuer = {rdnSequence, Issuer}} = TBS,
    error({unknown_ca, Issuer});
find_ca([], _Cert) ->
    error(unknown_ca);
find_ca([CA | Rest], Cert) ->
    case public_key:pkix_is_issuer(Cert, CA) of
        true -> CA;
        false -> find_ca(Rest, Cert)
    end.

check_cert(Cert) ->
    DPandCRLs = fetch_dp_and_crls(Cert),
    SCardConfig = application:get_env(rdpproxy, smartcard, []),
    CACertPath = proplists:get_value(ca_cert, SCardConfig,
        "/etc/ssl/cert.pem"),
    {ok, CAData} = file:read_file(CACertPath),
    Entries0 = public_key:pem_decode(CAData),
    Entries1 = [public_key:pkix_decode_cert(E, otp) || {'Certificate',E,_} <- Entries0],
    CA = find_ca(Entries1, Cert),
    Opts = [],
    {ok, _} = public_key:pkix_path_validation(CA, [Cert], Opts),
    CRLOpts = [
        {issuer_fun, {fun (_DP, CL, _Name, none) ->
            {ok, find_ca(Entries1, CL), []}
        end, none}}
    ],
    valid = public_key:pkix_crls_validate(Cert, DPandCRLs, CRLOpts).

challenge_slot(Piv, Slot, PubKey) ->
    Algo = alg_for_key(PubKey),
    Challenge = <<"rdpproxy cak challenge", 0,
        (crypto:strong_rand_bytes(16))/binary>>,
    Hash = crypto:hash(sha256, Challenge),
    {ok, [{ok, CardSig}]} = apdu_transform:command(Piv, {sign, Slot,
        Algo, Hash}),
    true = public_key:verify(Challenge, sha256, CardSig, PubKey).

get_dn_attr([], Attr) ->
    false;
get_dn_attr([#'AttributeTypeAndValue'{type = Attr, value = V} | Rest], Attr) ->
    V;
get_dn_attr([L | Rest], Attr) when is_list(L) ->
    case get_dn_attr(L, Attr) of
        false -> get_dn_attr(Rest, Attr);
        Other -> Other
    end;
get_dn_attr([_ | Rest], Attr) ->
    get_dn_attr(Rest, Attr).

check_cak(Piv, Rdr, SC0) ->
    {ok, [{ok, CAKCert}]} = apdu_transform:command(Piv, {read_cert, piv_card_auth}),
    #'OTPCertificate'{tbsCertificate = TBS} = CAKCert,
    #'OTPTBSCertificate'{subject = {rdnSequence, Subj},
                         serialNumber = Serial} = TBS,
    check_cert(CAKCert),
    PubKey = cert_to_pubkey(CAKCert),
    challenge_slot(Piv, piv_card_auth, PubKey),
    lager:debug("verified CAK: serial = ~.16B, subj = ~p", [Serial, Subj]),
    SCardConfig = application:get_env(rdpproxy, smartcard, []),
    case proplists:get_value(cak_ou_match, SCardConfig) of
        undefined ->
            ok;
        OrgUnit ->
            OrgUnitUtf8 = unicode:characters_to_binary(OrgUnit),
            OrgUnitLatin1 = unicode:characters_to_binary(OrgUnit, utf8, latin1),
            case get_dn_attr(Subj, ?'id-at-organizationalUnitName') of
                {utf8String, OrgUnitUtf8} -> ok;
                {_, OrgUnitLatin1} -> ok;
                Other -> error({no_ou_match, Other})
            end
    end,
    apdu_transform:end_transaction(Piv),
    {ok, Piv, Rdr, SC0}.

check_rdr([], SC0) ->
    rdpdr_scard:close(SC0),
    {error, no_scard_found};
check_rdr([Rdr | Rest], SC0) ->
    case rdpdr_scard:connect(Rdr, shared, {t0_or_t1, optimal}, SC0) of
        {ok, Mode, SC1} ->
            {ok, [Piv | _]} = apdu_stack:start_link(element(1, Mode),
                [nist_piv, iso7816_chain, iso7816, {rdpdr_scard_apdu, [SC1]}]),
            ok = apdu_transform:begin_transaction(Piv),
            case apdu_transform:command(Piv, select) of
                {ok, [{ok, #{version := V}}]} ->
                    case apdu_transform:command(Piv, read_chuid) of
                        {ok, [{ok, #{guid := <<Guid:128/big>>}}]} ->
                            lager:debug("PIV applet v~B in ~p, GUID ~.16B",
                                [V, Rdr, Guid]),
                            case apdu_transform:command(Piv, yk_get_version) of
                                {ok, [{ok, Version}]} ->
                                    lager:debug("YubiKey firmware version ~p",
                                        [Version]);
                                _ ->
                                    ok
                            end,
                            case apdu_transform:command(Piv, yk_get_serial) of
                                {ok, [{ok, Serial}]} ->
                                    lager:debug("YubiKey serial ~B", [Serial]);
                                _ ->
                                    ok
                            end,
                            case (catch check_cak(Piv, Rdr, SC1)) of
                                {'EXIT', Why} ->
                                    lager:debug("failed to verify cak: ~p",
                                        [Why]),
                                    apdu_transform:end_transaction(Piv),
                                    {ok, SC2} = rdpdr_scard:disconnect(leave, SC1),
                                    check_rdr(Rest, SC2);
                                Other ->
                                    Other
                            end;
                        _ ->
                            apdu_transform:end_transaction(Piv),
                            {ok, SC2} = rdpdr_scard:disconnect(leave, SC1),
                            check_rdr(Rest, SC2)
                    end;
                _ ->
                    apdu_transform:end_transaction(Piv),
                    {ok, SC2} = rdpdr_scard:disconnect(leave, SC1),
                    check_rdr(Rest, SC2)
            end;
        Err ->
            check_rdr(Rest, SC0)
    end.
