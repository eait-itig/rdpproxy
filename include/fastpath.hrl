%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-record(fp_pdu, {flags = [], signature, contents = []}).

-record(fp_inp_unknown, {type, remainder, flags}).
-record(fp_inp_scancode, {flags = [], action=down, code}).
-record(fp_inp_mouse, {action=move, buttons=[], point}).
-record(fp_inp_wheel, {point, clicks=0}).
-record(fp_inp_sync, {flags = []}).
-record(fp_inp_unicode, {code = 0, action = down}).
