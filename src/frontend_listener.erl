%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(frontend_listener).

-behaviour(gen_server).

-export([start_link/1]).
-export([accept_loop/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-spec start_link(Port :: integer()) -> {ok, pid()}.
start_link(Port) ->
	gen_server:start_link({local, frontend_listener}, ?MODULE, [Port], []).

-record(state, {sock, port, accpid}).

%% @private
init([Port]) ->
	process_flag(trap_exit, true),
	case gen_tcp:listen(Port, [binary, {active, false}, {reuseaddr, true}]) of
		{ok, Sock} ->
			Pid = spawn_link(?MODULE, accept_loop, [Sock, self(), wait]),
			ok = gen_tcp:controlling_process(Sock, Pid),
			Pid ! {self(), go},
			{ok, #state{port = Port, sock = Sock, accpid = Pid}};
		{error, Reason} ->
			{stop, Reason}
	end.

accept_loop(Sock, Parent, wait) ->
	receive
		{Parent, go} ->
			accept_loop(Sock, Parent, ok)
	end;
accept_loop(Sock, Parent, ok) ->
	{ok, FSock} = gen_tcp:accept(Sock),
	ok = gen_tcp:controlling_process(FSock, Parent),
	gen_server:cast(Parent, {accepted, FSock}),
	accept_loop(Sock, Parent, ok).

%% @private
handle_call(_Msg, _From, State) ->
	{noreply, State}.

%% @private
handle_cast({accepted, Sock}, State) ->
	{ok, Pid} = frontend:start_link(Sock),
	ok = gen_tcp:controlling_process(Sock, Pid),
	gen_fsm:send_event(Pid, control_given),
	{noreply, State};

handle_cast(_Msg, State) ->
	{noreply, State}.

%% @private
handle_info({'EXIT', Pid, Reason}, #state{port = Port, accpid = Pid} = State) ->
	case gen_tcp:listen(Port, [binary, {active, false}, {reuseaddr, true}, {packet, tpkt}]) of
		{ok, Sock} ->
			NewPid = spawn_link(?MODULE, accept_loop, [Sock, self(), wait]),
			ok = gen_tcp:controlling_process(Sock, NewPid),
			NewPid ! {self(), go},
			{noreply, State#state{accpid = NewPid, sock = Sock}};
		_ ->
			{noreply, State}
	end;

handle_info(_Msg, State) ->
	{noreply, State}.

%% @private
terminate(_Reason, _State) ->
	ok.

%% @private
% default handler
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.
