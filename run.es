#!/usr/bin/env escript
%% -*- erlang -*-
%%! -pa ebin/
main(_) ->
	application:start(crypto),
	application:start(public_key),
	application:start(ssl),
    rdpproxy:start(),
    %backend:start_link(self(), "teak.eait.uq.edu.au", 3389),
    receive
    	stop ->
    		done
    end.
