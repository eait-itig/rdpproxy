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
-include_lib("cairerl/include/cairerl.hrl").

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

uq_logo_bitmap() ->
	{ok, Logo} = cairerl_nif:png_read("uq-logo.png"),
	#cairo_image{width = W, height = H} = Logo,
	Image0 = #cairo_image{width=W, height=H, data = <<>>},
	{ok, _, Image1} = cairerl_nif:draw(Image0, [], [
		#cairo_pattern_create_for_surface{tag=uqlogo, image=Logo},
		#cairo_set_source{tag=uqlogo},
		#cairo_rectangle{x=0.0,y=0.0,width=float(W),height=float(H)},
		#cairo_fill{}
		]),
	Image1.

test_bitmap() ->
	ColourSetUqPurple = #cairo_set_source_rgba{r=16#49 / 256,g = 16#07 / 256,b = 16#5e / 256},
	ColourSetWhite = #cairo_set_source_rgba{r=0.95,g=0.95,b=1.0},
	Image0 = #cairo_image{width=300,height=30,data = <<>>},
	Ops = [
		ColourSetUqPurple,
		#cairo_rectangle{x=0.0, y=0.0, width=300.0, height=30.0},
		#cairo_fill{},

		ColourSetWhite,
		#cairo_select_font_face{family= <<"sans-serif">>},
		#cairo_set_font_size{size = 20.0},
		#cairo_text_extents{text = <<"something is fucky",0>>, tag = txte},
		#cairo_tag_deref{tag=txte, field=width, out_tag=txtw},
		#cairo_tag_deref{tag=txte, field=height, out_tag=txth},
		#cairo_translate{x = 150.0, y = 15.0},
		#cairo_scale{x = -0.5, y = 0.5},
		#cairo_translate{x = txtw, y = txth},
		#cairo_scale{x = -2.0, y = 2.0},
		#cairo_show_text{text = <<"something is fucky",0>>}
	],
	{ok, _, Image1} = cairerl_nif:draw(Image0, [], Ops),
	Image1.

startup(timeout, S = #state{frontend = F}) ->
	{W, H, Bpp} = gen_fsm:sync_send_event(F, get_canvas),
	Rt = #rect{topleft = {round(W/2 - 50), round(H/2 - 25)},
				 size = {100, 50}},
	gen_fsm:send_event(F, {send_update, #ts_update_orders{orders = [
		#ts_order_opaquerect{dest={0,0}, size={W,H}, color={16#49,16#07,16#5e}},
		#ts_order_opaquerect{dest=Rt#rect.topleft, size=Rt#rect.size, color={255,100,100}}
	]}}),
	LogoBitmap = #cairo_image{width = LogoW, height = LogoH} = uq_logo_bitmap(),
	TextBitmap = test_bitmap(),
	gen_fsm:send_event(F, {send_update, #ts_update_bitmaps{
		bitmaps = divide_bitmap(LogoBitmap, {round(W/2 - LogoW/2), round(H/4 - LogoH/2)})
	}}),
	gen_fsm:send_event(F, {send_update, #ts_update_bitmaps{
		bitmaps = divide_bitmap(TextBitmap, {round(W/2 - 150), round(H/4 + LogoH/2)})
	}}),
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
					{ok, Cookie} = session_mgr:store(#session{host = "gs208-1969.labs.eait.uq.edu.au", port = 3389, user = <<"ntadmin">>, domain = <<".">>, password = <<"beer'npizza">>}),
					gen_fsm:send_event(F, {redirect,
						Cookie, <<"uqawil16-mbp.eait.uq.edu.au">>,
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
