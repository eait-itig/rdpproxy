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

-export([start/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).
-export([reserve_ip/2, reserve_pool/2]).
-export([probe/2, save_cookie/2]).

-spec start(Pool :: session_ra:pool(), BaseSession :: session_ra:handle_state()) -> {ok, pid()}.
start(Pool, BaseSession = #{}) ->
    gen_fsm:start(?MODULE, [self(), Pool, BaseSession], []).

-record(?MODULE, {from, mref, pool, sess, hdl, retries, errs = 0}).

%% @private
init([From, Pool, Sess = #{user := U}]) ->
    lager:debug("allocating session for ~p", [U]),
    MRef = erlang:monitor(process, From),
    NextState = case Sess of
        #{ip := _Ip} -> reserve_ip;
        _ -> reserve_pool
    end,
    {ok, NextState, #?MODULE{mref = MRef, pool = Pool, from = From,
        sess = Sess}, 0}.

reserve_pool(timeout, S = #?MODULE{pool = Pool, sess = Sess}) ->
    #{user := U, password := Pw, domain := D} = Sess,
    case session_ra:reserve(Pool, U) of
        {ok, Hdl, HD0} ->
            Sess1 = HD0#{password => Pw, domain => D},
            S1 = S#?MODULE{sess = Sess1, hdl = Hdl, retries = 3, errs = 0},
            {next_state, probe, S1, 0};
        {error, no_hosts} ->
            lager:warning("no pool hosts available for ~p in ~p", [U, Pool]),
            {next_state, reserve_pool, S, 2000}
    end.

reserve_ip(timeout, S = #?MODULE{sess = Sess}) ->
    #{ip := Ip, user := U, password := Pw, domain := D} = Sess,
    {ok, Hdl, HD0} = session_ra:reserve_ip(U, Ip),
    Sess1 = HD0#{password => Pw, domain => D},
    S1 = S#?MODULE{sess = Sess1, hdl = Hdl, retries = unlimited, errs = 0},
    {next_state, probe, S1, 0}.

probe(timeout, S = #?MODULE{sess = Sess, hdl = Hdl, retries = R0, errs = E0}) ->
    #{ip := Ip, port := Port} = Sess,
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
            S#?MODULE.from ! {alloc_persistent_error, self(), no_ssl},
            {error, 2000, no_ssl};
        {error, bad_cert} ->
            S#?MODULE.from ! {alloc_persistent_error, self(), bad_cert},
            {error, 2000, bad_cert};
        {error, credssp_required} ->
            S#?MODULE.from ! {alloc_persistent_error, self(), credssp_required},
            {error, 2000, credssp_required};
        {error, econnrefused} ->
            T = if
                (E1 > 10) -> 10000;
                (E1 > 5) ->
                    S#?MODULE.from ! {alloc_persistent_error, self(), refused},
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
                    S#?MODULE.from ! {alloc_persistent_error, self(), down},
                    2000;
                true -> 1000
            end,
            {error, T, Reason};
        E ->
            lager:debug("probe failed on ~p: ~p", [Ip, E]),
            {error, 1000, E}
    end,
    case Ok of
        ok ->
            {next_state, save_cookie, S, 0};
        error ->
            case Retry of
                true ->
                    % Log errors even if we're in unlimited retries mode
                    case R1 of
                        unlimited when ((E1 rem 3) == 0) ->
                            ok = session_ra:host_error(Ip, Err);
                        _ -> ok
                    end,
                    {next_state, probe, S#?MODULE{retries = R1, errs = E1}, Timeout};
                false ->
                    ok = session_ra:alloc_error(Hdl, Err),
                    {next_state, reserve_pool, S, 1000}
            end
    end.

save_cookie(timeout, S = #?MODULE{sess = Sess0, hdl = Hdl}) ->
    {ok, Sess1} = session_ra:allocate(Hdl, Sess0),
    #{ip := Ip, user := U} = Sess1,
    lager:debug("allocated session on ~p for user ~p, cookie: ~p",
        [Ip, U, Hdl]),
    S#?MODULE.from ! {allocated_session, self(), Sess1},
    {stop, normal, S}.

handle_info({'DOWN', MRef, process, _, _}, _State, S = #?MODULE{mref = MRef}) ->
    {stop, normal, S};
handle_info(Msg, State, S = #?MODULE{}) ->
    ?MODULE:State(Msg, S).

%% @private
terminate(_Reason, _State, _Data) ->
    ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
    {ok, State}.
