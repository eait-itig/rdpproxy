#!/usr/bin/env escript
%% -*- erlang -*-
%%! -pa ebin/
main(_) ->
	[ok = application:start(X) || X <- [crypto, asn1, public_key, ssl]],
    rdpproxy:start(),
    %backend:start_link(self(), "teak.eait.uq.edu.au", 3389),
    receive
    	stop ->
    		done
    end.
