%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-record(cliprdr_caps, {flags = [], caps = []}).
-record(cliprdr_cap_general, {version = 2, flags = []}).
-record(cliprdr_monitor_ready, {flags = []}).
-record(cliprdr_format_list, {flags = [], formats = []}).
