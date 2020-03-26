%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2019 Alex Wilson <alex@uq.edu.au>
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

-module(host_alloc_fsm).

-behaviour(gen_fsm).

-include("session.hrl").

-export([start/1]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).
-export([reserve/2]).
-export([probe/2, save_cookie/2]).

-spec start(BaseSession :: #session{}) -> {ok, pid()}.
start(BaseSession = #session{}) ->
    gen_fsm:start(?MODULE, [self(), BaseSession], []).

-record(state, {from, mref, sess, hdl, retries, errs = 0}).

%% @private
init([From, Sess = #session{user = U}]) ->
    lager:debug("allocating session for ~p", [U]),
    MRef = erlang:monitor(process, From),
    case Sess of
        #session{host = undefined} ->
            {ok, reserve, #state{mref = MRef, from = From, sess = Sess}, 0};
        _ ->
            {ok, probe, #state{mref = MRef, from = From, sess = Sess, retries = unlimited}, 0}
    end.

reserve(timeout, S = #state{sess = Sess}) ->
    #session{user = U} = Sess,
    case pool_ra:reserve(U) of
        {ok, Hdl, Ip, Port} ->
            Sess1 = Sess#session{host = Ip, port = Port},
            S1 = S#state{sess = Sess1, hdl = Hdl, retries = 3, errs = 0},
            {next_state, probe, S1, 0};
        {error, no_hosts} ->
            lager:warning("no pool hosts available for ~p", [U]),
            {next_state, reserve, S, 2000}
    end.

probe(timeout, S = #state{sess = Sess, retries = R0, errs = E0}) ->
    #session{host = Ip, port = Port} = Sess,
    {R1, Retry} = case R0 of
        unlimited -> {unlimited, true};
        1 -> {0, false};
        N -> {N - 1, true}
    end,
    E1 = E0 + 1,
    {Ok, Timeout, Err} = case backend:probe(binary_to_list(Ip), Port) of
        ok ->
            {ok, 0, none};
        {error, no_ssl} ->
            S#state.from ! {alloc_persistent_error, self(), no_ssl},
            {error, 2000, no_ssl};
        {error, econnrefused} ->
            T = if
                (E1 > 10) -> 10000;
                (E1 > 5) ->
                    S#state.from ! {alloc_persistent_error, self(), refused},
                    5000;
                true -> 1000
            end,
            {error, T, econnrefused};
        {error, Reason} when (Reason =:= timeout) or (Reason =:= ehostunreach) ->
            T = if
                (E1 > 50) -> 10000;
                (E1 > 30) -> 5000;
                (E1 > 7) -> 2000;
                (E1 > 5) ->
                    S#state.from ! {alloc_persistent_error, self(), down},
                    2000;
                true -> 1000
            end,
            {error, T, Reason};
        E ->
            lager:debug("probe failed on ~p: ~p", [Ip, E]),
            {error, 1000, E}
    end,
    case Ok of
        ok -> {next_state, save_cookie, S, 0};
        error ->
            case Retry of
                true ->
                    {next_state, probe, S#state{retries = R1, errs = E1}, Timeout};
                false ->
                    case S of
                        #state{hdl = undefined} ->
                            pool_ra:host_error(Ip, Err);
                        #state{hdl = Hdl} ->
                            pool_ra:alloc_error(Hdl, Err)
                    end,
                    {next_state, reserve, S, 1000}
            end
    end.

save_cookie(timeout, S = #state{sess = Sess}) ->
    {ok, Cookie} = cookie_ra:create(Sess),
    case S of
        #state{hdl = undefined} -> ok;
        #state{hdl = Hdl} -> pool_ra:allocate(Hdl)
    end,
    lager:debug("allocated session on ~p for user ~p, cookie: ~p",
        [Sess#session.host, Sess#session.user, Cookie]),
    S#state.from ! {allocated_session, self(), Sess#session{cookie = Cookie}},
    {stop, normal, S}.

handle_info({'DOWN', MRef, process, _, _}, _State, S = #state{mref = MRef}) ->
    {stop, normal, S};
handle_info(Msg, State, S = #state{}) ->
    ?MODULE:State(Msg, S).

%% @private
terminate(_Reason, _State, _Data) ->
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
