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
    fuse:install(ldap_fuse, { {standard, 3, 10}, {reset, 30000} }),
    supervisor:start_link(?MODULE, []).

%% @private
start(_StartType, _StartArgs) ->
    start().

%% @private
stop(_State) ->
    ok.

%% @private
init(_Args) ->
    RiakSize = rdpproxy:config([riak, connections], 20),
    RiakHost = rdpproxy:config([riak, host], "localhost"),
    RiakPort = rdpproxy:config([riak, port], 8087),
    {ok, _Pid} = http_api:start(),

    LdapPools = lists:map(fun({Name,Conf}) ->
        poolboy:child_spec(Name,
            [{name, {local, Name}},
             {worker_module, ldap_pool},
             {size, 4},
             {max_overflow, 16}],
            [Conf])
    end, rdpproxy:config(ldap, [])),

    {ok, _} = timer:apply_interval(30000, db_cookie, expire, []),

    {ok, {
        {one_for_one, 60, 60},
        [
            {ui_fsm_sup,
                {ui_fsm_sup, start_link, []},
                permanent, infinity, supervisor, [ui_fsm, ui_fsm_sup]},
            {frontend_sup,
                {frontend_sup, start_link, [3389]},
                permanent, infinity, supervisor, [frontend, frontend_sup]},
            poolboy:child_spec(riakcp,
                [{name, {local, riakc_pool}},
                 {worker_module, riakc_pool},
                 {size, RiakSize},
                 {max_overflow, RiakSize*2}],
                [RiakHost, RiakPort])
        ] ++ LdapPools
    }}.
