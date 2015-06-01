%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(frontend_sup).

-behaviour(supervisor).
-export([start_link/1, init/1, start_frontend/1]).
-export([initial_listeners/1]).

start_link(Port) ->
    supervisor:start_link(?MODULE, [Port]).

start_frontend(Sup) ->
    supervisor:start_child(Sup, []).

%% @private
initial_listeners(Sup) ->
    [start_frontend(Sup) || _ <- lists:seq(1,20)],
    ok.

init([Port]) ->
    {ok, ListenSocket} = gen_tcp:listen(Port, [binary, {active, false}, {reuseaddr, true}]),
    spawn_link(?MODULE, initial_listeners, [self()]),
    Server = {undefined,
        {frontend, start_link, [ListenSocket, self()]},
        temporary, 1000, worker, [frontend]},
    {ok, {{simple_one_for_one, 60, 60}, [Server]}}.
