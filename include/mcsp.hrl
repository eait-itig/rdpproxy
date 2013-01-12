%% Generated by the Erlang ASN.1 compiler version:1.7
%% Purpose: Erlang record definitions for each named and unnamed
%% SEQUENCE and SET, and macro definitions for each value
%% definition,in module MCS-PROTOCOL-BER



-record('DomainParameters',{
maxChannelIds, maxUserIds, maxTokenIds, numPriorities, minThroughput, maxHeight, maxMCSPDUsize, protocolVersion}).

-record('Connect-Initial',{
callingDomainSelector, calledDomainSelector, upwardFlag, targetParameters, minimumParameters, maximumParameters, userData}).

-record('Connect-Response',{
result, calledConnectId, domainParameters, userData}).

-record('Connect-Additional',{
calledConnectId, dataPriority}).

-record('Connect-Result',{
result}).

-record('PlumbDomainIndication',{
heightLimit}).

-record('ErectDomainRequest',{
subHeight, subInterval}).

-record('ChannelAttributes_static',{
channelId}).

-record('ChannelAttributes_userId',{
joined, userId}).

-record('ChannelAttributes_private',{
joined, channelId, manager, admitted}).

-record('ChannelAttributes_assigned',{
channelId}).

-record('MergeChannelsRequest',{
mergeChannels, purgeChannelIds}).

-record('MergeChannelsConfirm',{
mergeChannels, purgeChannelIds}).

-record('PurgeChannelsIndication',{
detachUserIds, purgeChannelIds}).

-record('TokenAttributes_grabbed',{
tokenId, grabber}).

-record('TokenAttributes_inhibited',{
tokenId, inhibitors}).

-record('TokenAttributes_giving',{
tokenId, grabber, recipient}).

-record('TokenAttributes_ungivable',{
tokenId, grabber}).

-record('TokenAttributes_given',{
tokenId, recipient}).

-record('MergeTokensRequest',{
mergeTokens, purgeTokenIds}).

-record('MergeTokensConfirm',{
mergeTokens, purgeTokenIds}).

-record('PurgeTokensIndication',{
purgeTokenIds}).

-record('DisconnectProviderUltimatum',{
reason}).

-record('RejectMCSPDUUltimatum',{
diagnostic, initialOctets}).

-record('AttachUserRequest',{
}).

-record('AttachUserConfirm',{
result, initiator = asn1_NOVALUE}).

-record('DetachUserRequest',{
reason, userIds}).

-record('DetachUserIndication',{
reason, userIds}).

-record('ChannelJoinRequest',{
initiator, channelId}).

-record('ChannelJoinConfirm',{
result, initiator, requested, channelId = asn1_NOVALUE}).

-record('ChannelLeaveRequest',{
channelIds}).

-record('ChannelConveneRequest',{
initiator}).

-record('ChannelConveneConfirm',{
result, initiator, channelId = asn1_NOVALUE}).

-record('ChannelDisbandRequest',{
initiator, channelId}).

-record('ChannelDisbandIndication',{
channelId}).

-record('ChannelAdmitRequest',{
initiator, channelId, userIds}).

-record('ChannelAdmitIndication',{
initiator, channelId, userIds}).

-record('ChannelExpelRequest',{
initiator, channelId, userIds}).

-record('ChannelExpelIndication',{
channelId, userIds}).

-record('SendDataRequest',{
initiator, channelId, dataPriority, segmentation, userData}).

-record('SendDataIndication',{
initiator, channelId, dataPriority, segmentation, userData}).

-record('UniformSendDataRequest',{
initiator, channelId, dataPriority, segmentation, userData}).

-record('UniformSendDataIndication',{
initiator, channelId, dataPriority, segmentation, userData}).

-record('TokenGrabRequest',{
initiator, tokenId}).

-record('TokenGrabConfirm',{
result, initiator, tokenId, tokenStatus}).

-record('TokenInhibitRequest',{
initiator, tokenId}).

-record('TokenInhibitConfirm',{
result, initiator, tokenId, tokenStatus}).

-record('TokenGiveRequest',{
initiator, tokenId, recipient}).

-record('TokenGiveIndication',{
initiator, tokenId, recipient}).

-record('TokenGiveResponse',{
result, recipient, tokenId}).

-record('TokenGiveConfirm',{
result, initiator, tokenId, tokenStatus}).

-record('TokenPleaseRequest',{
initiator, tokenId}).

-record('TokenPleaseIndication',{
initiator, tokenId}).

-record('TokenReleaseRequest',{
initiator, tokenId}).

-record('TokenReleaseConfirm',{
result, initiator, tokenId, tokenStatus}).

-record('TokenTestRequest',{
initiator, tokenId}).

-record('TokenTestConfirm',{
initiator, tokenId, tokenStatus}).

