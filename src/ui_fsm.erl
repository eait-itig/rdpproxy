%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_fsm).
-behaviour(gen_fsm).

-include("rdpp.hrl").
-include("kbd.hrl").
-include("session.hrl").

-export([start_link/1]).
-export([startup/2]).
-export([init/1, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid()) -> {ok, pid()}.
start_link(Frontend) ->
	gen_fsm:start_link(?MODULE, [Frontend], []).

-record(state, {frontend}).

%% @private
init([Frontend]) ->
	{ok, startup, #state{frontend = Frontend}, 0}.

startup(timeout, S = #state{}) ->
	{next_state, startup, S}.

%% @private
terminate(_Reason, _State, _Data) ->
	ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
	{ok, State}.
