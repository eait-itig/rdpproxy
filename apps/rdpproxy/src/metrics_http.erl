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

-module(metrics_http).

-export([start/0]).
-export([init/2]).

start() ->
    Port = rdpproxy:config([metrics_http, port], 27600),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/metrics", metrics_http, []}
        ]}
    ]),
    {ok, App} = application:get_all_key(rdpproxy),
    Mods = proplists:get_value(modules, App),
    [Mod:register_metrics() || Mod <- Mods,
        erlang:function_exported(Mod, register_metrics, 0)],
    cowboy:start_clear(metrics_http, [{port, Port}],
        #{env => #{dispatch => Dispatch}}).

init(Req0, State) ->
    Data = prometheus_text_format:format(),
    Req1 = cowboy_req:reply(200,
        #{<<"content-type">> => <<"application/openmetrics-text">>},
        Data, Req0),
    {ok, Req1, State}.
