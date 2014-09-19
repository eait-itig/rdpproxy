#!/usr/bin/env escript
%% -*- erlang -*-
%%! -pa ebin/ -pa deps/cairerl/ebin/ -pa deps/lager/ebin -pa deps/riakc/ebin -pa deps/goldrush/ebin
main(_) ->
	[ok = application:start(X) || X <- [crypto, asn1, public_key, ssl, syntax_tools, compiler, goldrush, lager]],
    rdpproxy:start(),
    %backend:start_link(self(), "teak.eait.uq.edu.au", 3389),
    receive
    	stop ->
    		done
    end.
