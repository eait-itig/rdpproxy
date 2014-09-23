%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(rle_nif).

-export([compress/3, uncompress/3]).
-on_load(init/0).

init() ->
    PrivDir = case code:priv_dir(?MODULE) of
                  {error, _} ->
                      EbinDir = filename:dirname(code:which(?MODULE)),
                      AppPath = filename:dirname(EbinDir),
                      filename:join(AppPath, "priv");
                  Path ->
                      Path
              end,
    erlang:load_nif(filename:join(PrivDir, ?MODULE), 0).

-type bitmap() :: binary().
-type rle_bitmap() :: binary().

-spec compress(Pixels :: bitmap(), Width :: integer(), Height :: integer()) -> {ok, rle_bitmap()} | {error, term()}.
compress(_Pixels, _Width, _Height) ->
    error(bad_nif).

-spec uncompress(Compressed :: rle_bitmap(), Width :: integer(), Height :: integer()) -> {ok, bitmap()} | {error, term()}.
uncompress(_Compr, _W, _H) ->
    error(bad_nif).
