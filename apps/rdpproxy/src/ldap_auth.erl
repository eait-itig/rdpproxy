%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(ldap_auth).
-export([process/2]).

-include_lib("eldap/include/eldap.hrl").

process([], User) -> {true, User};
process([{Name, Config} | Rest], User) ->
	case (do_stage(Name, Config, User)) of
		{'EXIT', Err} -> lager:debug("ldap auth error: ~p", [Err]), {false, User};
		{true, User2} -> process(Rest, User2);
		{false, User2} -> {false, User2}
	end.

do_stage(Name, Config, User) ->
	Type = proplists:get_value(type, Config, search),
	do_stage(Type, Name, Config, User).

do_stage(search, Name, Config, User) ->
	Filter = build_query(proplists:get_value(filter, Config), User),
	[BindUser, BindPw] = proplists:get_value(bind, Config),
	Base = proplists:get_value(base, Config, ""),
	poolboy:transaction(Name, fun(L) ->
		ok = gen_server:call(L, {bind, BindUser, BindPw}),
		{ok, Res} = gen_server:call(L, {search, [{base, Base}, {filter, Filter}, {attributes, ["dn"]}]}),
		#eldap_search_result{entries = Ents} = Res,
		case Ents of
			[#eldap_entry{} | _] ->
				{true, User};
			[] ->
				lager:debug("failed to find LDAP user in search:~p, rejecting", [Name]),
				{false, User}
		end
	end);

do_stage(search_and_bind, Name, Config, User) ->
	Filter = build_query(proplists:get_value(filter, Config), User),
	[BindUser, BindPw] = proplists:get_value(bind, Config),
	Base = proplists:get_value(base, Config, ""),
	poolboy:transaction(Name, fun(L) ->
		ok = gen_server:call(L, {bind, BindUser, BindPw}),
		{ok, Res} = gen_server:call(L, {search, [{base, Base}, {filter, Filter}, {attributes, ["dn"]}]}),
		#eldap_search_result{entries = Ents} = Res,
		case Ents of
			[#eldap_entry{object_name = Dn} | _] ->
				case gen_server:call(L, {bind, Dn, proplists:get_value(<<"password">>, User)}) of
					ok -> {true, User};
					_ -> {false, User}
				end;
			[] ->
				lager:debug("failed to find LDAP user in search_and_bind:~p, rejecting", [Name]),
				{false, User}
		end
	end);

do_stage(_, _Name, _Config, User) ->
	{false, User}.

build_query(List, User) when is_list(List) ->
	case io_lib:printable_list(List) of
		true -> List;
		_ -> [build_query(I, User) || I <- List]
	end;
build_query(Atom, User) when is_atom(Atom) ->
	case proplists:get_value(atom_to_binary(Atom, utf8), User) of
		B when is_binary(B) -> B;
		[B | _] when is_binary(B) -> B;
		S when is_list(S) ->
			case io_lib:printable_list(S) of
				true -> S;
				_ -> error({bad_ldap_qval, Atom, S})
			end;
		Other -> error({bad_ldap_qval, Atom, Other})
	end;
build_query({Method, Args}, User) when is_atom(Method) and is_list(Args) ->
	apply(eldap, Method, [build_query(Arg, User) || Arg <- Args]);
build_query(Term, _User) ->
	Term.
