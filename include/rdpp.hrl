%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-include("kbd.hrl").

-define(ROP_BLACKNESS, 16#00).
-define(ROP_SRCCOPY, 16#CC).
-define(ROP_SRCPAINT, 16#EE).
-define(ROP_PATCOPY, 16#F0).
-define(ROP_WHITENESS, 16#FF).
-define(ROP_SRCAND, 16#88).
-define(ROP_SRCINVERT, 16#66).

-record(ts_security, {secflags = [], random=[]}).
-record(ts_info, {secflags = [], codepage=0, flags = [mouse, noaudio], compression='8k', domain="", username="", password="", shell="", workdir=""}).
-record(ts_license_vc, {secflags = []}).
-record(ts_heartbeat, {secflags = [], period=30, warning=3, reconnect=5}).

-record(ts_cap_general, {os=[unix, native_x11], flags=[suppress_output, refresh_rect, short_bitmap_hdr, autoreconnect, long_creds, salted_mac]}).
-record(ts_cap_bitmap, {bpp, flags=[compression, multirect, resize], width=1024, height=768}).
-record(ts_cap_share, {channel}).
-record(ts_cap_order, {flags=[negotiate, zeroboundsdeltas, colorindex], orders=[dstblt,patblt,scrblt,memblt,mem3blt,lineto,savebitmap,multidstblt,multipatblt,multiscrblt,multiopaquerect,fastindex,polygonsc,polygoncb,polyline,fastglyph,ellipsesc,ellipsecb,index]}).
-record(ts_cap_input, {flags=[mousex, scancodes, unicode], kbd_layout=?KBDL_US, kbd_type=?KBD_IBM101, kbd_sub_type=0, kbd_fun_keys=12, ime=""}).
-record(ts_cap_font, {flags=[fontlist]}).
-record(ts_cap_pointer, {flags=[color], cache_size=25}).
-record(ts_cap_vchannel, {flags=[], chunksize=1600}).
-record(ts_cap_control, {flags=[], control=never, detach=never}).
-record(ts_cap_activation, {helpkey=0, wmkey=0, helpexkey=0}).
-record(ts_cap_multifrag, {maxsize=64*1024}).

-record(ts_demand, {channel, shareid, sourcedesc=[], capabilities=[]}).
-record(ts_confirm, {channel, shareid, sourcedesc=[], capabilities=[]}).
-record(ts_deactivate, {channel, shareid, sourcedesc=[]}).
-record(ts_redir, {channel, shareid, sessionid, username=[], domain=[], password=[], cookie=[], flags=[logon], address, fqdn}).

-record(ts_sharedata, {channel, priority=high, comptype=none, flags=[], shareid, data={}}).
-record(ts_sync, {user}).
-record(ts_control, {action, grantid, controlid}).
-record(ts_fontlist, {}).
-record(ts_fontmap, {}).

-record(ts_order_opaquerect, {flags=[], dest, size, color=[0,0,0]}).
-record(ts_order_srcblt, {flags=[], dest, src, size, rop = ?ROP_SRCCOPY}).
-record(ts_order_line, {flags=[], start, finish, rop=?ROP_PATCOPY, color=[0,0,0]}).
-record(ts_update_orders, {orders=[]}).

-record(ts_bitmap, {dest, size, bpp=24, compress=no, data}).
-record(ts_update_bitmaps, {bitmaps=[]}).

-record(ts_inpevt_sync, {flags=[]}).
-record(ts_inpevt_key, {code=0, action=down, flags=[]}).
-record(ts_inpevt_unicode, {code=0, action=down}).
-record(ts_inpevt_mouse, {action=move, buttons=[], point}).
-record(ts_inpevt_wheel, {clicks=0, point}).
-record(ts_input, {events=[]}).
