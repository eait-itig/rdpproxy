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
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([start_link/1]).
-export([startup/2, login/2]).
-export([init/1, handle_info/3, terminate/3, code_change/4]).

-spec start_link(Frontend :: pid()) -> {ok, pid()}.
start_link(Frontend) ->
	gen_fsm:start_link(?MODULE, [Frontend], []).

-record(state, {frontend, mref, w, h, bpp, root}).

%% @private
init([Frontend]) ->
	gen_fsm:send_event(Frontend, {subscribe, self()}),
	MRef = monitor(process, Frontend),
	{ok, startup, #state{mref = MRef, frontend = Frontend}, 0}.

slice_bitmap(_I, _Xs, []) -> [];
slice_bitmap(_I, _Xs, [_Y]) -> [];
slice_bitmap(I = #cairo_image{}, Xs, [FromY, ToY | RestY]) ->
	slice_bitmap_x(I, Xs, [FromY, ToY | RestY]) ++
	slice_bitmap(I, Xs, [ToY | RestY]).
slice_bitmap_x(_I, [], _) -> [];
slice_bitmap_x(_I, [_X], _) -> [];
slice_bitmap_x(I = #cairo_image{}, [FromX, ToX | RestX], [FromY, ToY | RestY]) ->
	Image0 = #cairo_image{width = ToX - FromX, height = ToY - FromY, data = <<>>},
	{ok, _, Image1} = cairerl_nif:draw(Image0, [], [
		#cairo_pattern_create_for_surface{tag=img, image=I},
		#cairo_pattern_translate{tag=img, x=float(FromX), y=float(FromY)},
		#cairo_set_source{tag=img},
		#cairo_rectangle{width = float(ToX - FromX), height = float(ToY - FromY)},
		#cairo_fill{}
	]),
	[{FromX, FromY, Image1} | slice_bitmap_x(I, [ToX | RestX], [FromY, ToY | RestY])].

divide_bitmap(I = #cairo_image{}) ->
	divide_bitmap(I, {0,0}).
divide_bitmap(I = #cairo_image{width = W, height = H}, {X0,Y0})
		when (W * H > 10000) ->
	XInt = 4 * (round(math:sqrt(W / H * 10000)) div 4),
	YInt = 4 * (round(math:sqrt(H / W * 10000)) div 4),
	XIntervals = lists:seq(0, W, XInt) ++ [W],
	YIntervals = lists:seq(0, H, YInt) ++ [H],
	Slices = slice_bitmap(I, XIntervals, YIntervals),
	lists:flatmap(fun({X, Y, Slice}) ->
		divide_bitmap(Slice, {X0 + X, Y0 + Y})
	end, Slices);
divide_bitmap(I = #cairo_image{data = D, width = W, height = H}, {X,Y}) ->
	{ok, Compr} = rle_nif:compress(D, W, H),
	[#ts_bitmap{dest={X,Y}, size={W,H}, bpp=24, data = Compr, comp_info =
		#ts_bitmap_comp_info{flags = [compressed]}}].

rect_to_ts_order(#rect{dest={X,Y}, size={W,H}, color={R,G,B}}) ->
	#ts_order_opaquerect{dest={round(X),round(Y)},
		size={round(W),round(H)},
		color={round(R*256), round(G*256), round(B*256)}}.

orders_to_updates([]) -> [];
orders_to_updates(L = [#rect{} | _]) ->
	{Rects, Rest} = lists:splitwith(fun(#rect{}) -> true; (_) -> false end, L),
	[#ts_update_orders{orders = lists:map(fun rect_to_ts_order/1, Rects)} |
		orders_to_updates(Rest)];
orders_to_updates([#image{dest = {X,Y}, image = Im} | Rest]) ->
	[#ts_update_bitmaps{
		bitmaps = divide_bitmap(Im, {round(X), round(Y)})
	} | orders_to_updates(Rest)].

send_orders(F, Orders) ->
	lists:foreach(fun(U) ->
		gen_fsm:send_event(F, {send_update, U})
	end, orders_to_updates(Orders)).

startup(timeout, S = #state{frontend = F}) ->
	{W, H, Bpp} = gen_fsm:sync_send_event(F, get_canvas),
	UQPurple = {16#49 / 256, 16#07 / 256, 16#5e / 256},
	{Root, _, []} = ui:new({float(W), float(H)}),
	Events = [
		{ [{id, root}], {set_bgcolor, UQPurple} },
		{ [{id, root}], {add_child, #widget{id = hlayout, handler = hlayout_handler}} },
		{ [{id, hlayout}], init },
		{ [{id, hlayout}], {set_margin, 100} },
		{ [{id, hlayout}], {add_child, #widget{id = logo, handler = png_image_handler}} },
		{ [{id, hlayout}], {add_child, #widget{id = loginlyt, handler = vlayout_handler, size = {W/4, H}}} },
		{ [{id, loginlyt}], init },
		{ [{id, loginlyt}], {add_child, #widget{id = testlbl, handler = label_handler, size = {W/4, 20.0}}} },
		{ [{id, loginlyt}], {add_child, #widget{id = foolbl, handler = label_handler, size = {W/4, 20.0}}} },
		{ [{id, loginlyt}], {add_child, #widget{id = txt, handler = textinput_handler, size = {W/4, 30.0}}} },
		{ [{id, loginlyt}], {add_child, #widget{id = testbtn, handler = button_handler, size = {120.0, 40.0}}} }
	],
	{Root2, Orders0, []} = ui:handle_events(Root, Events),
	send_orders(F, Orders0),
	Events2 = [
		{ [{id, logo}], {init, "uq-logo.png"} },
		{ [{id, testlbl}], {init, left, <<"This is a test.", 0>>} },
		{ [{id, testlbl}], {set_bgcolor, UQPurple} },
		{ [{id, foolbl}], {init, left, <<"This is a foo test.", 0>>} },
		{ [{id, foolbl}], {set_bgcolor, UQPurple} },
		{ [{id, txt}], {init, <<"Username">>} },
		{ [{id, testbtn}], {init, <<"Click me", 0>>} }
	],
	{Root3, Orders, []} = ui:handle_events(Root2, Events2),
	send_orders(F, Orders),
	{next_state, login, S#state{w = W, h = H, bpp = Bpp, root = Root3}}.

login({input, F, Evt}, S = #state{frontend = F, root = Root}) ->
	case Evt of
		#ts_inpevt_mouse{point = P} ->
			Event = { [{contains, P}], Evt },
			{Root2, Orders, UiEvts} = ui:handle_events(Root, [Event]),
			lists:foreach(fun(UiEvt) ->
				gen_fsm:send_event(self(), {ui, UiEvt})
			end, UiEvts),
			send_orders(F, Orders),
			{next_state, login, S#state{root = Root2}};
		#ts_inpevt_key{code = 1} ->
			gen_fsm:send_event(F, close),
			{stop, normal, S};
		#ts_inpevt_key{code = 15} ->
			io:format("handle tab?\n"),
			{next_state, login, S};
		#ts_inpevt_key{code = Code} ->
			Event = { [{tag, focus}], Evt },
			{Root2, Orders, UiEvts} = ui:handle_events(Root, [Event]),
			lists:foreach(fun(UiEvt) ->
				gen_fsm:send_event(self(), {ui, UiEvt})
			end, UiEvts),
			send_orders(F, Orders),
			{next_state, login, S#state{root = Root2}};
		_ ->
			{next_state, login, S}
	end;

login({ui, {clicked, testbtn}}, S = #state{frontend = F, root = Root}) ->
	{ok, Cookie} = session_mgr:store(#session{
		host = "gs208-1969.labs.eait.uq.edu.au", port = 3389,
		user = <<"ntadmin">>, domain = <<".">>, password = <<"beer'npizza">>}),
	gen_fsm:send_event(F, {redirect,
		Cookie, <<"uqawil16-mbp.eait.uq.edu.au">>,
		<<"ntadmin">>, <<".">>, <<"beer'npizza">>}),
	{stop, normal, S}.

handle_info({'DOWN', MRef, process, _, _}, State, S = #state{mref = MRef}) ->
	{stop, normal, S}.

%% @private
terminate(_Reason, _State, _Data) ->
	ok.

%% @private
% default handler
code_change(_OldVsn, State, _Data, _Extra) ->
	{ok, State}.
