%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_fsm).
-behaviour(gen_fsm).

-include("rdpp.hrl").
-include("kbd.hrl").
-include("session.hrl").

-export([start_link/1]).
-export([startup/2, nohighlight/2, highlight/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid()) -> {ok, pid()}.
start_link(Frontend) ->
	gen_fsm:start_link(?MODULE, [Frontend], []).

-record(state, {frontend, mref, w, h, bpp, rect}).
-record(rect, {topleft, size}).

rect_contains(#rect{topleft = {X,Y}, size = {W,H}}, {Xp, Yp}) ->
	(Xp > X) andalso (Yp > Y) andalso (Xp < X + W) andalso (Yp < Y + H).

%% @private
init([Frontend]) ->
	gen_fsm:send_event(Frontend, {subscribe, self()}),
	MRef = monitor(process, Frontend),
	{ok, startup, #state{mref = MRef, frontend = Frontend}, 0}.

startup(timeout, S = #state{frontend = F}) ->
	{W, H, Bpp} = gen_fsm:sync_send_event(F, get_canvas),
	Rt = #rect{topleft = {round(W/2 - 50), round(H/2 - 25)},
				 size = {100, 50}},
	gen_fsm:send_event(F, {send_update, #ts_update_orders{orders = [
		#ts_order_opaquerect{dest=Rt#rect.topleft, size=Rt#rect.size, color={255,100,100}}
	]}}),
	{next_state, nohighlight, S#state{w = W, h = H, bpp = Bpp, rect = Rt}}.

nohighlight({input, F, Evt}, S = #state{frontend = F, w = W, h = H, rect = Rt}) ->
	case Evt of
		#ts_inpevt_mouse{action = move, point = P = {X,Y}} ->
			case rect_contains(Rt, P) of
				true ->
					gen_fsm:send_event(F, {send_update, #ts_update_orders{orders = [
						#ts_order_opaquerect{dest=Rt#rect.topleft, size=Rt#rect.size, color={255,200,200}}
					]}}),
					{next_state, highlight, S};
				_ ->
					{next_state, nohighlight, S}
			end;
		_ ->
			{next_state, nohighlight, S}
	end.

highlight({input, F, Evt}, S = #state{frontend = F, h = H, w = W, rect = Rt}) ->
	case Evt of
		#ts_inpevt_mouse{action = down, point = P = {X,Y}, buttons = [1]} ->
			case rect_contains(Rt, P) of
				true ->
					{ok, Cookie} = session_mgr:store(#session{host = "gs208-1974.labs.eait.uq.edu.au", port = 3389}),
					gen_fsm:send_event(F, {redirect,
						Cookie, <<"uqawil16-mbp">>,
						<<"ntadmin">>, <<".">>, <<"beer'npizza">>}),
					{stop, normal, S};

				_ ->
					{next_state, highlight, S}
			end;
		#ts_inpevt_mouse{action = move, point = P = {X,Y}} ->
			case rect_contains(Rt, P) of
				true ->
					{next_state, highlight, S};
				_ ->
					gen_fsm:send_event(F, {send_update, #ts_update_orders{orders = [
						#ts_order_opaquerect{dest=Rt#rect.topleft, size=Rt#rect.size, color={255,100,100}}
					]}}),
					{next_state, nohighlight, S}
			end;
		_ ->
			{next_state, highlight, S}
	end.

handle_info({'DOWN', MRef, process, _, _}, State, S = #state{mref = MRef}) ->
	{stop, normal, S}.

%% @private
terminate(_Reason, _State, _Data) ->
	ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
	{ok, State}.
