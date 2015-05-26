%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(mcsgcc).

-include("mcsgcc.hrl").
-include("mcsp.hrl").
-include("gccp.hrl").

-export([encode_ci/1, decode_ci/1]).
-export([decode_cr/1, encode_cr/1]).
-export([decode_dpdu/1, encode_dpdu/1]).

-export([decode/1, encode/1]).
-export([pretty_print/1]).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(mcs_ci);
?pp(mcs_cr);
?pp(mcs_edr);
?pp(mcs_aur);
?pp(mcs_auc);
?pp(mcs_cjr);
?pp(mcs_cjc);
?pp(mcs_tir);
?pp(mcs_data);
?pp(mcs_srv_data);
?pp(mcs_dpu);
pretty_print(_, _) ->
    no.

decode_try_methods(Bin, []) -> {error, {nomethod, Bin}};
decode_try_methods(Bin, Methods) ->
    [Method|Rest] = Methods,
    case ?MODULE:Method(Bin) of
        {ok, Rec} -> {ok, Rec};
        Error ->
            %lager:debug("tried: ~p, got: ~p", [Method, Error]),
            decode_try_methods(Bin, Rest)
    end.

decode(Bin) ->
    Methods = [decode_dpdu, decode_ci, decode_cr],
    decode_try_methods(Bin, Methods).

encode(#mcs_ci{} = Rec) -> encode_ci(Rec);
encode(#mcs_cr{} = Rec) -> encode_cr(Rec);
encode(#mcs_edr{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_tic{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_cjc{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_auc{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_data{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_srv_data{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_dpu{} = Rec) -> encode_dpdu(Rec);
encode(_) -> {error, bad_mcsgcc}.

padding_only(Bin) ->
    Sz = bit_size(Bin),
    <<0:Sz>> = Bin.

decode_dpdu(Bin) ->
    case mcsp_per:decode('DomainMCSPDU', Bin) of
        {ok, {sendDataRequest, #'SendDataRequest'{initiator = User, channelId = Channel, dataPriority = Priority, userData = Data}}, <<>>} ->
            {ok, #mcs_data{user = User, channel = Channel, priority = Priority, data = list_to_binary(Data)}};
        {ok, {sendDataIndication, #'SendDataIndication'{initiator = User, channelId = Channel, dataPriority = Priority, userData = Data}}, <<>>} ->
            {ok, #mcs_srv_data{user = User, channel = Channel, priority = Priority, data = list_to_binary(Data)}};
        {ok, {erectDomainRequest, #'ErectDomainRequest'{subHeight = Height, subInterval = Interval}}, <<>>} ->
            {ok, #mcs_edr{height = Height, interval = Interval}};
        {ok, {attachUserRequest, #'AttachUserRequest'{}}, Rem} ->
            padding_only(Rem),
            {ok, #mcs_aur{}};
        {ok, {attachUserConfirm, #'AttachUserConfirm'{result = Result, initiator = UserId}},<<>>} ->
            {ok, #mcs_auc{status = Result, user = UserId}};
        {ok, {channelJoinRequest, #'ChannelJoinRequest'{initiator = UserId, channelId = Channel}}, <<>>} ->
            {ok, #mcs_cjr{user = UserId, channel = Channel}};
        {ok, {channelJoinConfirm, #'ChannelJoinConfirm'{result = Result, initiator=UserId, requested=Channel}}, <<>>} ->
            {ok, #mcs_cjc{user = UserId, status = Result, channel = Channel}};
        {ok, {tokenInhibitRequest, #'TokenInhibitRequest'{initiator=UserId, tokenId=Token}}, <<>>} ->
            {ok, #mcs_tir{user = UserId, token = Token}};
        {ok, {tokenInhibitConfirm, #'TokenInhibitConfirm'{initiator=UserId, tokenId=Token, result=Status, tokenStatus=TokenStatus}}, <<>>} ->
            {ok, #mcs_tic{user = UserId, token = Token, status = Status, token_status = TokenStatus}};
        {ok, {Atom, _}, <<>>} ->
            {error, {nothandled, Atom}};
        Other ->
            Other
    end.

encode_dpdu(#mcs_tic{user = UserId, token = Token, status = Status, token_status = TokenStatus}) ->
    mcsp_per:encode('DomainMCSPDU', {tokenInhibitConfirm, #'TokenInhibitConfirm'{result = Status, tokenStatus = TokenStatus, initiator = UserId, tokenId = Token}});
encode_dpdu(#mcs_auc{status = Result, user = UserId}) ->
    mcsp_per:encode('DomainMCSPDU', {attachUserConfirm, #'AttachUserConfirm'{result = Result, initiator = UserId}});
encode_dpdu(#mcs_cjc{channel = Channel, status = Result, user = UserId}) ->
    mcsp_per:encode('DomainMCSPDU', {channelJoinConfirm, #'ChannelJoinConfirm'{result = Result, initiator = UserId, requested = Channel, channelId = Channel}});
encode_dpdu(#mcs_data{user = UserId, channel = Channel, priority = Priority, data = Binary}) ->
    mcsp_per:encode('DomainMCSPDU', {sendDataRequest, #'SendDataRequest'{initiator = UserId, channelId = Channel, dataPriority = Priority, segmentation = 3, userData = Binary}});
encode_dpdu(#mcs_srv_data{user = UserId, channel = Channel, priority = Priority, data = Binary}) ->
    mcsp_per:encode('DomainMCSPDU', {sendDataIndication, #'SendDataIndication'{initiator = UserId, channelId = Channel, dataPriority = Priority, segmentation = 3, userData = Binary}});
encode_dpdu(#mcs_dpu{reason = Reason}) ->
    mcsp_per:encode('DomainMCSPDU', {disconnectProviderUltimatum, #'DisconnectProviderUltimatum'{reason = Reason}});
encode_dpdu(_) -> {error, bad_dpdu}.

decode_ci(Bin) ->
    case mcsp_ber:decode('Connect-Initial', Bin) of
        {ok, CI, Rem} ->
            padding_only(Rem),
            Tgt = CI#'Connect-Initial'.targetParameters,
            Initial = #mcs_ci{calling = CI#'Connect-Initial'.callingDomainSelector,
                              called = CI#'Connect-Initial'.calledDomainSelector,
                              max_channels = Tgt#'DomainParameters'.maxChannelIds,
                              max_users = Tgt#'DomainParameters'.maxUserIds,
                              max_tokens = Tgt#'DomainParameters'.maxTokenIds,
                              num_priorities = Tgt#'DomainParameters'.numPriorities,
                              min_throughput = Tgt#'DomainParameters'.minThroughput,
                              max_height = Tgt#'DomainParameters'.maxHeight,
                              max_size = Tgt#'DomainParameters'.maxHeight,
                              version = Tgt#'DomainParameters'.protocolVersion},

            CDData = list_to_binary(CI#'Connect-Initial'.userData),
            case gccp_per:decode('ConnectData', CDData) of
                {ok, CD, CDRem} ->
                    if byte_size(CDRem) > 0 ->
                        lager:warning("ci connectdata is carrying ~B extra bytes", [byte_size(CDRem)]);
                    true -> ok end,
                    CPDUData = list_to_binary(CD#'ConnectData'.connectPDU),
                    case gccp_per:decode('ConnectGCCPDU', <<CPDUData/binary, CDRem/binary>>) of
                        {ok, {conferenceCreateRequest, CCR}, <<>>} ->
                            NameRec = CCR#'ConferenceCreateRequest'.conferenceName,
                            [#'UserData_SETOF'{key={h221NonStandard, "Duca"}, value=ClientData}] = CCR#'ConferenceCreateRequest'.userData,
                            {ok, Initial#mcs_ci{conf_name = NameRec#'ConferenceName'.numeric, data = list_to_binary(ClientData)}};
                        Other ->
                            Other
                    end;
                Other ->
                    Other
            end;
        Other ->
            Other
    end.

decode_cr(Bin) ->
    case mcsp_ber:decode('Connect-Response', Bin) of
        {ok, CR, Rem} ->
            padding_only(Rem),
            Tgt = CR#'Connect-Response'.domainParameters,
            Initial = #mcs_cr{called = CR#'Connect-Response'.calledConnectId,
                              mcs_result = CR#'Connect-Response'.result,
                              max_channels = Tgt#'DomainParameters'.maxChannelIds,
                              max_users = Tgt#'DomainParameters'.maxUserIds,
                              max_tokens = Tgt#'DomainParameters'.maxTokenIds,
                              num_priorities = Tgt#'DomainParameters'.numPriorities,
                              min_throughput = Tgt#'DomainParameters'.minThroughput,
                              max_height = Tgt#'DomainParameters'.maxHeight,
                              max_size = Tgt#'DomainParameters'.maxHeight,
                              version = Tgt#'DomainParameters'.protocolVersion},

            CDData = list_to_binary(CR#'Connect-Response'.userData),
            case gccp_per:decode('ConnectData', CDData) of
                {ok, CD, CDRem} ->
                    if byte_size(CDRem) > 0 ->
                        lager:warning("cr connectdata is carrying ~B extra bytes", [byte_size(CDRem)]);
                    true -> ok end,
                    CPDUData = list_to_binary(CD#'ConnectData'.connectPDU),
                    case gccp_per:decode('ConnectGCCPDU', <<CPDUData/binary,CDRem/binary>>) of
                        {ok, {conferenceCreateResponse, CCR}, <<>>} ->
                            Node = CCR#'ConferenceCreateResponse'.nodeID,
                            Tag = CCR#'ConferenceCreateResponse'.tag,
                            Result = CCR#'ConferenceCreateResponse'.result,
                            [#'UserData_SETOF'{key={h221NonStandard, "McDn"}, value=ClientData}] = CCR#'ConferenceCreateResponse'.userData,
                            CDataBin = list_to_binary(ClientData),
                            %Data = <<CDataBin/binary, CDRem/binary>>,
                            {ok, Initial#mcs_cr{node = Node, tag = Tag, result = Result, data = CDataBin}};
                        Other ->
                            Other
                    end;
                Other ->
                    Other
            end;
        Other ->
            Other
    end.

encode_cr(#mcs_cr{} = McsCr) ->
    UserData = #'UserData_SETOF'{key = {h221NonStandard, "McDn"}, value = binary_to_list(McsCr#mcs_cr.data)},
    CCR = #'ConferenceCreateResponse'{nodeID = McsCr#mcs_cr.node, tag = McsCr#mcs_cr.tag, result = McsCr#mcs_cr.result, userData = [UserData]},
    {ok, GccPdu} = gccp_per:encode('ConnectGCCPDU', {conferenceCreateResponse, CCR}),
    CD = #'ConnectData'{connectPDU = binary_to_list(GccPdu)},
    {ok, CDData} = gccp_per:encode('ConnectData', CD),
    Params = #'DomainParameters'{maxChannelIds = McsCr#mcs_cr.max_channels,
                               maxUserIds = McsCr#mcs_cr.max_users,
                               maxTokenIds = McsCr#mcs_cr.max_tokens,
                               numPriorities = McsCr#mcs_cr.num_priorities,
                               minThroughput = McsCr#mcs_cr.min_throughput,
                               maxHeight = McsCr#mcs_cr.max_height,
                               maxMCSPDUsize = McsCr#mcs_cr.max_size,
                               protocolVersion = McsCr#mcs_cr.version},
    CR = #'Connect-Response'{calledConnectId = McsCr#mcs_cr.called,
                             result = McsCr#mcs_cr.mcs_result,
                             domainParameters = Params,
                             userData = binary_to_list(CDData)},
    {ok, CRData} = mcsp_ber:encode('Connect-Response', CR),

    {ok, CRData}.

encode_ci(#mcs_ci{} = McsCI) ->
    UserData = #'UserData_SETOF'{key = {h221NonStandard, "Duca"}, value = binary_to_list(McsCI#mcs_ci.data)},
    NameRec = #'ConferenceName'{numeric = McsCI#mcs_ci.conf_name},
    CCR = #'ConferenceCreateRequest'{conferenceName = NameRec, userData = [UserData]},
    {ok, GccPdu} = gccp_per:encode('ConnectGCCPDU', {conferenceCreateRequest, CCR}),
    CD = #'ConnectData'{connectPDU = binary_to_list(GccPdu)},
    {ok, CDData} = gccp_per:encode('ConnectData', CD),
    TargetParams = #'DomainParameters'{maxChannelIds = McsCI#mcs_ci.max_channels,
                                       maxUserIds = McsCI#mcs_ci.max_users,
                                       maxTokenIds = McsCI#mcs_ci.max_tokens,
                                       numPriorities = McsCI#mcs_ci.num_priorities,
                                       minThroughput = McsCI#mcs_ci.min_throughput,
                                       maxHeight = McsCI#mcs_ci.max_height,
                                       maxMCSPDUsize = McsCI#mcs_ci.max_size,
                                       protocolVersion = McsCI#mcs_ci.version},
    MinParams = #'DomainParameters'{maxChannelIds = 1, maxUserIds = 2, maxTokenIds = 1, numPriorities = 1, minThroughput = 0, maxHeight = 1, maxMCSPDUsize = 1024, protocolVersion = 2},
    MaxParams = #'DomainParameters'{maxChannelIds = 1024, maxUserIds = 1 bsl 20, maxTokenIds = 1024, numPriorities = 3, minThroughput = 1024, maxHeight = 1024, maxMCSPDUsize = 1 bsl 20, protocolVersion = 2},
    CI = #'Connect-Initial'{callingDomainSelector = McsCI#mcs_ci.calling,
                            calledDomainSelector = McsCI#mcs_ci.called,
                            upwardFlag = true,
                            targetParameters = TargetParams,
                            minimumParameters = MinParams,
                            maximumParameters = MaxParams,
                            userData = binary_to_list(CDData)},
    {ok, CIData} = mcsp_ber:encode('Connect-Initial', CI),

    {ok, CIData}.
