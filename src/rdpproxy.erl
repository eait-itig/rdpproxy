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

%% @doc Starts the rdpproxy application.
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
		{one_for_one, 60, 600},
		[
			{frontend_sup,
				{frontend_sup, start_link, [3389]},
				permanent, infinity, supervisor, [frontend, frontend_sup]},
			{ui_sup,
				{ui_sup, start_link, []},
				permanent, infinity, supervisor, [ui_fsm, ui_sup]},
			{session_mgr,
				{session_mgr, start_link, []},
				permanent, 10, worker, [session_mgr]}
		]
	}}.
