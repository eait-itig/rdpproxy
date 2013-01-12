%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-record(x224_cr, {cdt=0, dst, src, class=0, rdp_cookie="", rdp_protocols=[ssl]}).
-record(x224_cc, {cdt=0, dst, src, class=0, rdp_status=ok, rdp_flags=[], rdp_selected=[ssl], rdp_error=none}).
-record(x224_dt, {roa=0, eot=1, tpdunr=0, data}).
-record(x224_dr, {dst, src, reason}).
