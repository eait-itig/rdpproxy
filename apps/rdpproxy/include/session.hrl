%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-record(session, {cookie=auto, expiry, host, port, user, password, domain}).
-define(COOKIE_TTL, 8*3600).
