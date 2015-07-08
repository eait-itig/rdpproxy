%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
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
	Allowed = http_api:peer_allowed(Ip, PeerIp),
	if (not Allowed) ->
		lager:debug("denied status update request from ~p for host ~p", [PeerIp, Ip]);
	true -> ok end,
	{(not Allowed), Req, S#state{peer = PeerIp}}.

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
	Updates = lists:sort([proplists:get_value(<<"updated">>, Plist) || {_Ip, Plist} <- Metas]),
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
