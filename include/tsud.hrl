%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-include("kbd.hrl").

-record(tsud_core, {version=[8,4], width, height, sas=16#aa03, kbd_layout=?KBDL_US, client_build=2600, client_name="localhost", kbd_type=?KBD_IBM101, kbd_sub_type=0, kbd_fun_keys=12, color='16bpp', colors=['16bpp'], capabilities=[errinfo], selected=[], conn_type=unknown}).

-record(tsud_svr_core, {version=[8,4], requested=[], capabilities=[]}).

-record(tsud_svr_net, {iochannel, channels=[]}).

-record(tsud_svr_security, {method=none, level=none, random="", certificate=""}).

-record(tsud_security, {methods=[]}).

-record(tsud_cluster, {flags=[], version=4, sessionid=none}).

-record(tsud_net, {channels=[]}).
-record(tsud_net_channel, {name=[], priority=low, flags=[]}).
