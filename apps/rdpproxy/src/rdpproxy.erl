%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
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

-module(rdpproxy).

-behaviour(supervisor).
-behaviour(application).

-export([start/0, start/2, stop/1, init/1]).
-export([config/1, config/2]).

dpath_resolve(Item, []) -> Item;
dpath_resolve(List, ['_' | Rest]) ->
    [dpath_resolve(X, Rest) || X <- List];
dpath_resolve(Plist, [Key | Rest]) when is_atom(Key) or is_binary(Key) ->
    dpath_resolve(proplists:get_value(Key, Plist), Rest);
dpath_resolve(List, [Index | Rest]) when is_integer(Index) ->
    dpath_resolve(lists:nth(Index, List), Rest).

config(KeyOrDPath) -> config(KeyOrDPath, undefined).
config([ConfigKey | DPath], Default) ->
    case application:get_env(rdpproxy, ConfigKey) of
        undefined -> Default;
        {ok, Other} -> case dpath_resolve(Other, DPath) of
            undefined -> Default;
            Other2 -> Other2
        end
    end;
config(ConfigKey, Default) ->
    case application:get_env(rdpproxy, ConfigKey) of
        undefined -> Default;
        {ok, Other} -> Other
    end.

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
    {ok, _Pid} = http_api:start(),

    _ = (catch conn_ra:start()),
    _ = (catch session_ra:start()),
    {ok, _} = timer:apply_interval(5000, conn_ra, tick, []),
    {ok, _} = timer:apply_interval(10000, session_ra, tick, []),

    {ok, {
        #{strategy => one_for_one, intensity => 60, period => 60},
        [
            #{id => ui_fsm_sup,
              start => {ui_fsm_sup, start_link, []},
              type => supervisor},
            #{id => frontend_sup,
              start => {rdp_server_sup, start_link, [3389, frontend]},
              type => supervisor}
        ]
    }}.
