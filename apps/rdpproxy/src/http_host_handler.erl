%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(http_host_handler).
-behaviour(cowboy_handler).

-export([init/2]).
-export([allowed_methods/2, forbidden/2, content_types_provided/2, resource_exists/2,
		 content_types_accepted/2]).
-export([from_json/2, to_json/2]).

-record(state, {opts, ip, meta, peer}).

init(Req, Opts) ->
	IpBin = cowboy_req:binding(ip, Req),
	{cowboy_rest, Req, #state{opts = Opts, ip = IpBin}}.

allowed_methods(Req, S = #state{ip = undefined}) ->
	{[<<"GET">>, <<"HEAD">>, <<"OPTIONS">>], Req, S};
allowed_methods(Req, S = #state{}) ->
	{[<<"GET">>, <<"HEAD">>, <<"OPTIONS">>, <<"PUT">>], Req, S}.

forbidden(Req, S = #state{ip = undefined}) ->
	{false, Req, S};
forbidden(Req, S = #state{ip = Ip}) ->
    {PeerIp, _PeerPort} = cowboy_req:peer(Req),
    {(not http_api:peer_allowed(Ip, PeerIp)), Req, S#state{peer = PeerIp}}.

content_types_provided(Req, S = #state{}) ->
	Types = [
		{{<<"application">>, <<"json">>, '*'}, to_json}
	],
	{Types, Req, S}.

resource_exists(Req, S = #state{ip = undefined}) ->
	case db_host_meta:find(status, <<"available">>) of
		{ok, Metas} when length(Metas) > 0 ->
			{true, Req, S#state{meta = Metas}};
		_ ->
			{false, Req, S}
	end;
resource_exists(Req, S = #state{ip = Ip}) ->
	case db_host_meta:get(Ip) of
		{ok, Meta} -> {true, Req, S#state{meta = Meta}};
		_ -> {false, Req, S}
	end.

content_types_accepted(Req, S = #state{}) ->
	Types = [
		{{<<"application">>, <<"json">>, '*'}, from_json}
	],
	{Types, Req, S}.

to_json(Req, S = #state{ip = undefined, meta = Metas}) ->
	Updates = lists:sort([proplists:get_value(<<"updated">>, Plist) || {Ip, Plist} <- Metas]),
	LatestUpdate = lists:last(Updates),
	Now = calendar:datetime_to_gregorian_seconds(erlang:localtime()),
	Json = [
		{count, length(Metas)},
		{last_update, Now - LatestUpdate}
	],
	{jsx:encode(Json), Req, S};
to_json(Req, S = #state{meta = Meta}) ->
	{jsx:encode(Meta), Req, S}.

from_json(Req, S = #state{ip = Ip, peer = Peer}) ->
	{ok, Json, Req2} = cowboy_req:body(Req),
	Meta = jsx:decode(Json),
	PeerBin = iolist_to_binary(io_lib:format("~B.~B.~B.~B", tuple_to_list(Peer))),
	Meta2 = jsxd:set([<<"hypervisor">>], PeerBin, Meta),
	case db_host_meta:put(Ip, Meta2) of
		ok -> {true, Req2, S};
		Err -> lager:error("put returned ~p", [Err]), {false, Req2, S}
	end.
