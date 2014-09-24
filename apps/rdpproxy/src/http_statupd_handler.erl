%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(http_statupd_handler).
-behaviour(cowboy_http_handler).

-export([init/3, handle/2, terminate/3]).

-record(state, {}).

init(_Transport, Req, _Options) ->
    {ok, Req, #state{}}.

terminate(_Reason, _Req, _State) ->
    ok.

handle(Req, S = #state{}) ->
    {ok, Req}.
