%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-type color() :: {Red :: float(), Green :: float(), Blue :: float()}.
-type point() :: {X :: float(), Y :: float()}.
-type size() :: {Width :: float(), Height :: float()}.

-record(rect, {dest = {0.0, 0.0} :: point(), size :: size(), color :: color()}).
-record(image, {dest = {0.0, 0.0} :: point(), image :: cairerl:image()}).
-type order() :: #rect{} | #image{}.

-record(widget, {id :: term(),
				 tags = [] :: [atom()],
				 dest = {0.0, 0.0} :: point(),
				 size = {0.0, 0.0} :: size(),
				 handler = error(no_handler) :: atom(),
				 state :: term(),
				 orders = [] :: [order()],
				 children = []}).
-type widget() :: #widget{}.
