%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(session).
-behaviour(gen_fsm).

-export([start_link/1]).
-export([init/1, handle_info/3, terminate/2, code_change/3]).

-spec start_link(Frontend :: pid()) -> {ok, pid()}.
start_link(Frontend) ->
    gen_fsm:start_link(?MODULE, [Frontend], []).

-record(data, {frontend}).

%% @private
init([Frontend]) ->
    process_flag(trap_exit, true),
    {ok, connected, #data{frontend = Frontend}}.

%% @private
handle_info({'EXIT', Pid, Reason}, State, Data) ->
    {next_state, State, Data};

handle_info(_Msg, State, Data) ->
    {next_state, State, Data}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
