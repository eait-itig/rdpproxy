%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_sup).

-behaviour(supervisor).
-export([start_link/0, init/1, start_ui/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_ui(Frontend) ->
    supervisor:start_child(?MODULE, [Frontend]).

init([]) ->
    Ui = {undefined,
        {ui_fsm, start_link, []},
        transient, 1000, worker, [ui_fsm]},
    {ok, {{simple_one_for_one, 60, 600}, [Ui]}}.
