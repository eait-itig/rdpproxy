%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-include("kbd.hrl").

-record(ts_security, {secflags = [], random=[]}).
-record(ts_info, {secflags = [], codepage=0, flags = [mouse, noaudio], compression='8k', domain="", username="", password="", shell="", workdir=""}).
-record(ts_license_vc, {secflags = []}).

-record(ts_cap_general, {os=[unix, other], flags=[long_creds]}).
-record(ts_cap_bitmap, {bpp, flags=[multirect], width=1024, height=768}).
-record(ts_cap_share, {channel=16#3ea}).
-record(ts_cap_input, {flags=[scancodes, unicode], kbd_layout=?KBDL_US, kbd_type=?KBD_IBM101, kbd_sub_type=0, kbd_fun_keys=12, ime=""}).
-record(ts_cap_font, {flags=[fontlist]}).
-record(ts_cap_pointer, {flags=[color], cache_size=16}).

-record(ts_demand, {channel=16#3ea, shareid=0, sourcedesc=[], capabilities=[]}).
-record(ts_confirm, {channel=16#3ea, shareid=0, sourcedesc=[], capabilities=[]}).
-record(ts_deactivate, {channel=16#3ea, shareid=0}).
-record(ts_redir, {channel=16#3ea, shareid=0}).

-record(ts_sharedata, {channel=16#3ea, priority=low, comptype=none, flags=[], shareid=0, data={}}).
