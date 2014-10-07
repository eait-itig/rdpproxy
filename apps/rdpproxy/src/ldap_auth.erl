%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ldap_auth).
-export([process/2]).

-include_lib("eldap/include/eldap.hrl").

process([], User) -> {true, User};
process([{Name, Config} | Rest], User) ->
	case (do_stage(Name, Config, User)) of
		{'EXIT', _} -> {false, User};
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
		[#eldap_entry{} | _] = Ents,
		{true, User}
	end);

do_stage(search_and_bind, Name, Config, User) ->
	Filter = build_query(proplists:get_value(filter, Config), User),
	[BindUser, BindPw] = proplists:get_value(bind, Config),
	Base = proplists:get_value(base, Config, ""),
	poolboy:transaction(Name, fun(L) ->
		ok = gen_server:call(L, {bind, BindUser, BindPw}),
		{ok, Res} = gen_server:call(L, {search, [{base, Base}, {filter, Filter}, {attributes, ["dn"]}]}),
		#eldap_search_result{entries = Ents} = Res,
		[#eldap_entry{object_name = Dn} | _] = Ents,
		case gen_server:call(L, {bind, Dn, proplists:get_value(<<"password">>, User)}) of
			ok -> {true, User};
			_ -> {false, User}
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
