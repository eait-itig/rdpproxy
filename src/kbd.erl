%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(kbd).

-include("kbd.hrl").
-export([process_scancode/1]).

process_scancode(Code) ->
    Codes = ?KBD_SCANCODES,
    if (Code < 0) orelse (Code >= size(Codes)) ->
        Code;
    true ->
        case element(Code + 1, Codes) of
            null -> Code;
            Other -> Other
        end
    end.
