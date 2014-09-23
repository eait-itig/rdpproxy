%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-include_lib("rdp_proto/include/kbd.hrl").

-record(tsud_core, {version=[8,1], width, height, sas=16#aa03, kbd_layout=?KBDL_US, client_build=2600, client_name="localhost", kbd_type=?KBD_IBM101, kbd_sub_type=0, kbd_fun_keys=12, color='24bpp', colors=['24bpp'], capabilities=[errinfo], selected=[], conn_type=unknown}).

-record(tsud_svr_core, {version=[8,1], requested=[], capabilities=[]}).
-record(tsud_svr_net, {iochannel, channels=[]}).
-record(tsud_svr_security, {method=none, level=none, random="", certificate=""}).
-record(tsud_svr_msgchannel, {channel}).
-record(tsud_svr_multitransport, {flags=[]}).

-record(tsud_security, {methods=[]}).
-record(tsud_cluster, {flags=[], version=4, sessionid=none}).
-record(tsud_net, {channels=[]}).
-record(tsud_net_channel, {name=[], priority=low, flags=[]}).
-record(tsud_monitor, {flags=[], monitors=[]}).
-record(tsud_monitor_def, {left, top, right, bottom, flags=[]}).
-record(tsud_msgchannel, {flags = []}).
-record(tsud_monitor_ex, {flags = [], monitors=[]}).
-record(tsud_monitor_ex_attr, {phys_width, phys_height, angle, desktop_scale, device_scale}).
-record(tsud_multitransport, {flags = []}).

-record(tsud_unknown, {type, data}).
