#!/usr/bin/env escript
%% -*- erlang -*-
%%! -name rdpproxy@127.0.0.1 -env ERL_LIBS ./apps:./deps -config rel/files/app.config
main(_) ->
	[{ok, ok} = {application:load(X), application:start(X)} || X <- [sasl, crypto, asn1, public_key, ssl, syntax_tools, compiler, goldrush, lager, ranch, cowlib, cowboy, cairerl, poolboy, protobuffs, fuse, riak_pb, riakc, rdp_proto, rdp_ui]],
	application:load(rdpproxy),
    rdpproxy:start(),
    %backend:start_link(self(), "teak.eait.uq.edu.au", 3389),
    shell:start(),
    receive
    	stop ->
    		done
    end.
