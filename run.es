#!/usr/bin/env escript
%% -*- erlang -*-
%%! -env ERL_LIBS ./apps:./deps
main(_) ->
	[ok = application:start(X) || X <- [crypto, asn1, public_key, ssl, syntax_tools, compiler, goldrush, lager, rdp_proto, rdp_ui]],
    rdpproxy:start(),
    %backend:start_link(self(), "teak.eait.uq.edu.au", 3389),
    receive
    	stop ->
    		done
    end.
