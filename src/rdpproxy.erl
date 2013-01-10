%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(rdpproxy).

-behaviour(supervisor).
-behaviour(application).

-export([start/0, start/2, stop/1, init/1]).

%% @doc Starts the swarm application.
start() ->
	supervisor:start_link(?MODULE, []).

%% @private
start(_StartType, _StartArgs) ->
	start().

%% @private
stop(_State) ->
	ok.

%% @private
init(_Args) ->
	{ok, {
		{one_for_one, 20, 60},
		[
			{webui, {spooky, start_link, [webui]}, permanent, 10, worker, [webui]}
		]
	}}.
