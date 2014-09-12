-define(sec_flags, [flagshi_valid, heartbeat, autodetect_rsp, autodetect_req, salted_mac, redirection, encrypt_license, skip, license, info, ignore_seqno, reset_seqno, encrypt, multitrans_rsp, multitrans_req, security]).
-define(sec_types, [autodetect_rsp, autodetect_req, redirection, license, info, multitrans_rsp, multitrans_req, security, heartbeat]).

-define(cc_prot_flags, [{skip,28}, credssp_early, skip, credssp, ssl]).

-define(ts_cap_general_flags, [{skip, 5}, short_bitmap_hdr, {skip, 5}, salted_mac, autoreconnect, long_creds, skip, fastpath, refresh_rect, suppress_output]).

-define(ts_cap_order_flags, [{skip,8}, extra, solid_pattern_brush_only, colorindex, skip, zeroboundsdeltas, skip, negotiate, skip]).
-define(ts_cap_orders, [
        {dstblt,8}, {patblt,8}, {scrblt,8}, {memblt,8}, {mem3blt,8}, {skip,16}, {drawninegrid,8},
        {lineto,8}, {multidrawninegrid,8}, {skip,8}, {savebitmap,8}, {skip,24}, {multidstblt,8},
        {multipatblt,8}, {multiscrblt,8}, {multiopaquerect,8}, {fastindex,8}, {polygonsc,8},
        {polygoncb,8}, {polyline,8}, {skip,8}, {fastglyph,8}, {ellipsesc,8}, {ellipsecb,8},
        {index,8}, {skip,32}
    ]).

-define(ts_cap_input_flags, [{skip, 10}, fastpath2, unicode, fastpath, mousex, skip, scancodes]).

-define(ts_cap_bitmap_flags, [{skip,4}, skip_alpha, subsampling, dynamic_bpp, skip, resize, compression, multirect]).

-define(ts_inpevt_sync_flags, [{skip,12}, kanalock, capslock, numlock, scrolllock]).

-define(ts_info_perf_flags, [{skip,23}, composition, font_smoothing, no_cursor_settings, no_cursor_shadow, skip, no_themes, no_menu_anim, no_full_win_drag, no_wallpaper]).
-define(ts_info_flags, [
                {skip,6}, rail_hd, {skip,2}, no_video, audio_in, saved_creds, no_audio, smartcard_pin,
                mouse_wheel, logon_errors, rail, force_encrypt, remote_console_audio, {skip,4},
                windows_key, compression, logon_notify, maximize_shell, unicode, autologoin, skip,
                disable_salute, mouse
            ]).
