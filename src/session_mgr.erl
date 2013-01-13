%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(session_mgr).

-behaviour(gen_server).

-include("session.hrl").
-compile({no_auto_import,[get/1]}).

-export([start_link/0]).
-export([store/1, get/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-spec start_link() -> {ok, pid()}.
start_link() ->
	gen_server:start_link({local, session_mgr}, ?MODULE, [], []).

-spec store(Rec :: #session{}) -> {ok, Cookie :: binary()}.
store(#session{cookie=auto} = Session) ->
	{ok, Cookie} = gen_server:call(session_mgr, gen_cookie),
	case get(Cookie) of
		{error, notfound} ->
			store(Session#session{cookie = Cookie});
		_ ->
			store(Session)
	end;
store(Session) ->
	ets:insert(sessions, Session),
	{ok, Session#session.cookie}.

-spec get(Cookie ::binary()) -> {ok, #session{}} | {error, notfound}.
get(Cookie) ->
	{ResL, _} = rpc:multicall(ets, lookup, [sessions, Cookie]),
	case lists:flatten(ResL) of
		[#session{} = Sess] ->
			{ok, Sess};
		_ ->
			{error, notfound}
	end.

-record(state, {alphabet}).

%% @private
init([]) ->
	process_flag(trap_exit, true),
	random:seed(erlang:now()),
	sessions = ets:new(sessions, [public, named_table, set, {write_concurrency, true}, {read_concurrency, true}, {keypos, 2}]),
	Alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.",
	Alphabet = list_to_tuple(Alpha),
	{ok, #state{alphabet = Alphabet}}.

gen_cookie(0, Data, _) -> Data;
gen_cookie(N, SoFar, Alpha) ->
	M = random:uniform(tuple_size(Alpha)),
	C = element(M, Alpha),
	gen_cookie(N-1, <<SoFar/binary, C>>, Alpha).

%% @private
handle_call(gen_cookie, _From, #state{alphabet = Alpha} = State) ->
	Randomness = gen_cookie(16, <<>>, Alpha),
	{reply, {ok, Randomness}, State};

handle_call(_Msg, _From, State) ->
	{noreply, State}.

%% @private
handle_cast(_Msg, State) ->
	{noreply, State}.

%% @private
handle_info(_Msg, State) ->
	{noreply, State}.

%% @private
terminate(_Reason, _State) ->
	ok.

%% @private
% default handler
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.
