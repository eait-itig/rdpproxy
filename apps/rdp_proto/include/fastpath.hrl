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

-record(ts_surface_set_bits, {
	dest :: {X :: integer(), Y :: integer()},
	size :: {W :: integer(), H :: integer()},
	bpp = 24 :: integer(),
	codec :: integer(),
	data :: binary()
}).
-record(ts_surface_stream_bits, {
	dest :: {X :: integer(), Y :: integer()},
	size :: {W :: integer(), H :: integer()},
	bpp = 24 :: integer(),
	codec :: integer(),
	data :: binary()
}).
-record(ts_surface_frame_marker, {
	action :: start | finish,
	frame :: integer()
}).
-record(ts_update_surfaces, {
	surfaces = [] :: [#ts_surface_set_bits{} | #ts_surface_stream_bits{} | #ts_surface_frame_marker{}]
}).
