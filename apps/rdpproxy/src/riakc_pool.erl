%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(riakc_pool).
-export([start_link/1]).

start_link(Args) ->
    apply(riakc_pb_socket, start_link, Args).
