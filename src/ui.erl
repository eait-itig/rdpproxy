%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui).
-include("rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([new/1, handle_events/2, select/2, print/1]).
-export([
    default_handler/2, root_handler/2, png_image_handler/2,
    hlayout_handler/2, vlayout_handler/2, label_handler/2,
    button_handler/2, textinput_handler/2
    ]).
-export([textinput_get_text/1]).

-spec new(Size :: size()) -> {widget(), [order()]}.
new(Size) ->
    Root = #widget{id = root, handler = root_handler, size = Size, dest = {0.0, 0.0}},
    handle_events(Root, [{ [{id, root}], init }]).

-type selector() :: {id, term()} |
                    {contains, point()} |
                    {handler, atom()} |
                    {tag, atom()}.

-spec rect_contains(Dest :: point(), Size :: size(), Point :: point()) -> boolean().
rect_contains({X0, Y0}, {W, H}, {X, Y}) ->
    (X >= X0) andalso (Y >= Y0) andalso
    (X =< X0 + W) andalso (Y =< Y0 + H).

-spec selector_matches(widget(), selector()) -> boolean().
selector_matches(W, {id, Id}) -> W#widget.id =:= Id;
selector_matches(W, {handler, H}) -> W#widget.handler =:= H;
selector_matches(W, {contains, P}) -> rect_contains({0,0}, W#widget.size, P);
selector_matches(W, {tag, T}) -> lists:member(T, W#widget.tags).

-spec collect_orders(widget()) -> [order()].
collect_orders(W = #widget{orders = O, children = Ks}) ->
    O ++ lists:flatmap(fun(K) -> offset_orders(K#widget.dest, collect_orders(K)) end, Ks).

-spec offset_orders(point(), [order()]) -> [order()].
offset_orders(_O, []) -> [];
offset_orders(O = {X0, Y0}, [R = #rect{dest = {X, Y}} | Rest]) ->
    [R#rect{dest = {X0 + X, Y0 + Y}} | offset_orders(O, Rest)];
offset_orders(O = {X0, Y0}, [I = #image{dest = {X, Y}} | Rest]) ->
    [I#image{dest = {X0 + X, Y0 + Y}} | offset_orders(O, Rest)].

-spec offset_selectors(point(), [selector()]) -> [selector()].
offset_selectors(_O, []) -> [];
offset_selectors(O = {X0, Y0}, [{contains, {X, Y}} | Rest]) ->
    [{contains, {X - X0, Y - Y0}} | offset_selectors(O, Rest)];
offset_selectors(O, [Other | Rest]) ->
    [Other | offset_selectors(O, Rest)].

offset_event(O = {X0, Y0}, Evt = #ts_inpevt_mouse{point = {X, Y}}) ->
    Evt#ts_inpevt_mouse{point = {X - X0, Y - Y0}};
offset_event(_O, Evt) -> Evt.

print(W) ->
    print(W, []).
print(#widget{dest = D, size = S, handler = H, id = Id, children = Kids}, Indent) ->
    io:format("~s#widget{id = ~p, dest = ~p, size = ~p, handler = ~p}\n", [Indent, Id, D, S, H]),
    lists:foreach(fun(Kid) ->
        print(Kid, [16#20 | Indent])
    end, Kids).

select(W = #widget{children = []}, [{contains, Pt}]) ->
    case selector_matches(W, {contains, Pt}) of
        true ->
            [W];
        false ->
            []
    end;
select(W = #widget{}, [Selector = {Type, _}]) ->
    case selector_matches(W, Selector) of
        true when Type =/= contains ->
            [W];
        _ ->
            lists:flatmap(fun(Kid) ->
                select(Kid, offset_selectors(W#widget.dest, [Selector]))
            end, W#widget.children)
    end;
select(W = #widget{}, [Selector = {Type, _} | SelRest]) ->
    case selector_matches(W, Selector) of
        true when Type =/= contains ->
            lists:flatmap(fun(Kid) ->
                select(Kid, offset_selectors(W#widget.dest, SelRest))
            end, W#widget.children);
        _ ->
            lists:flatmap(fun(Kid) ->
                select(Kid, offset_selectors(W#widget.dest, [Selector | SelRest]))
            end, W#widget.children)
    end.

handle_events(W = #widget{id = root}, []) -> {W, [], []};
handle_events(W = #widget{id = root}, [{ui, Event} | Rest]) ->
    {W2, RestOrders, RestUiEvts} = handle_events(W, Rest),
    {W2, RestOrders, [Event | RestUiEvts]};
handle_events(W = #widget{id = root}, [{Selector, Event} | Rest]) ->
    {W2, Orders, MoreEvts} = handle(W, Selector, Event),
    {W3, RestOrders, RestUiEvts} = handle_events(W2, Rest ++ MoreEvts),
    {W3, lists:flatten([Orders, RestOrders]), RestUiEvts}.

handle(W = #widget{handler = H, children = [], orders = OldOrders}, [{contains, Pt}], Event) ->
    case selector_matches(W, {contains, Pt}) of
        true ->
            case ?MODULE:H(Event, W) of
                {ok, W2 = #widget{orders = OldOrders, children = []}, MoreEvts} ->
                    {W2, [], MoreEvts};
                {ok, W2 = #widget{orders = Orders}, MoreEvts} ->
                    {W2, Orders, MoreEvts}
            end;
        false ->
            {W, [], []}
    end;
handle(W = #widget{handler = H, orders = OldOrders, children = Kids}, [Selector = {Type, _}], Event) ->
    Action = case selector_matches(W, Selector) of
        true when Type =/= contains -> deliver;
        true when Type =:= contains ->
            case lists:any(fun(K = #widget{dest = KD}) ->
                    [OffsetSel] = offset_selectors(KD, [Selector]),
                    selector_matches(K, OffsetSel) end, Kids) of
                false -> deliver;
                true -> recurse
            end;
        _ -> recurse
    end,
    case Action of
        deliver ->
            case ?MODULE:H(Event, W) of
                {ok, W2 = #widget{orders = OldOrders, children = Kids}, MoreEvts} ->
                    {W2, [], MoreEvts};
                {ok, W2 = #widget{}, MoreEvts} ->
                    {W2, collect_orders(W2), MoreEvts}
            end;
        recurse ->
            NewKOs = lists:map(fun(Kid) ->
                handle(Kid, offset_selectors(Kid#widget.dest, [Selector]),
                    offset_event(Kid#widget.dest, Event))
            end, Kids),
            handle_recurse(W, NewKOs)
    end;
handle(W = #widget{dest = D, children = K, handler = H}, [Selector = {Type, _} | SelRest], Event) ->
    NewKOs = case selector_matches(W, Selector) of
        true when Type =/= contains ->
            lists:map(fun(Kid = #widget{dest = KD}) ->
                handle(Kid, offset_selectors(KD, SelRest), offset_event(KD, Event))
            end, K);
        _ ->
            lists:map(fun(Kid = #widget{dest = KD}) ->
                handle(Kid, offset_selectors(KD, [Selector | SelRest]), offset_event(KD, Event))
            end, K)
    end,
    handle_recurse(W, NewKOs).

handle_recurse(W = #widget{dest = D, handler = H, orders = OldOrders, children = Kids}, NewKOs) ->
    NewKids = [K || {K, O, Es} <- NewKOs],
    Evts = lists:flatmap(fun({K, O, Es}) -> Es end, NewKOs),
    W2 = W#widget{children = NewKids},
    case lists:any(fun({_, [], _}) -> false; ({_, _, _}) -> true end, NewKOs) of
        false ->
            {W2, [], Evts};
        true ->
            case ?MODULE:H({children_updated, Kids}, W2) of
                {ok, W3 = #widget{orders = OldOrders, children = NewKids}, MoreEvts} ->
                    Orders = lists:flatmap(fun({K = #widget{dest = KD}, O, _Es}) ->
                        offset_orders(K#widget.dest, O)
                    end, NewKOs),
                    {W3, Orders, Evts ++ MoreEvts};
                {ok, W3 = #widget{}, MoreEvts} ->
                    {W3, collect_orders(W3), Evts ++ MoreEvts}
            end
    end.

default_handler({children_updated, _OldKids}, Wd = #widget{}) ->
    {ok, Wd, []};
default_handler({add_child, K}, Wd = #widget{children = Kids}) ->
    K2 = case K#widget.id of
        undefined -> K#widget{id = make_ref()};
        _ -> K
    end,
    {ok, Wd#widget{children = Kids ++ [K2]}, []};
default_handler({remove_child, Sel}, Wd = #widget{children = Kids}) ->
    {_Deleted, Kept} = lists:partition(fun(K) ->
        selector_matches(K, Sel)
    end, Kids),
    {ok, Wd#widget{children = Kept}, []};
default_handler(#ts_inpevt_mouse{action=move}, Wd) ->
    MouseWasIn = select(Wd, [{tag, mouse_in}]),
    Evts = [{ [{id, Id}], mouse_out } || W = #widget{id = Id} <- MouseWasIn, W =/= Wd],
    {ok, Wd, Evts};
default_handler(#ts_inpevt_mouse{}, Wd) ->
    {ok, Wd, []};
default_handler(Event, Wd = #widget{id = Id, handler = H}) ->
    io:format("<widget ~p (~p)> ignored event ~p\n", [Id, H, Event]),
    {ok, Wd, []}.

-record(root_state, {bgcolor = {0,0,0}, focus=[]}).
root_handler(init, Wd = #widget{size = Sz}) ->
    State = #root_state{},
    {ok, Wd#widget{state = State, orders = [
        #rect{size = Sz, color = State#root_state.bgcolor}
    ]}, []};
root_handler(focus_next, Wd = #widget{state = S}) ->
    #root_state{focus = Focus} = S,
    Focusable = select(Wd, [{tag, focusable}]),
    ToFocus = case lists:dropwhile(fun(K) -> not lists:member(K#widget.id, Focus) end, Focusable) of
        [_InFocus, Next | _Rest] -> Next;
        _ -> [Next | _] = Focusable, Next
    end,
    NewIds = [ToFocus#widget.id],
    FocusEvts = [{ [{id, Id}], focus } || Id <- NewIds],
    {ok, Wd, FocusEvts};
root_handler({children_updated, _OldKids}, Wd = #widget{children = NewKids, state = S = #root_state{focus = OldFocus}}) ->
    NewFocus = select(Wd, [{tag, focus}]),
    case [K#widget.id || K <- NewFocus] of
        OldFocus ->
            {ok, Wd, []};
        AllNewIds ->
            NewIds = AllNewIds -- OldFocus,
            UnfocusEvts = [{ [{id, Id}], blur } || Id <- OldFocus],
            S2 = S#root_state{focus = NewIds},
            {ok, Wd#widget{state = S2}, UnfocusEvts}
    end;
root_handler({add_child, K}, Wd = #widget{children = Kids, size = Sz}) ->
    case Kids of
        [] -> ok;
        _ -> io:format("warning: root widget replacing child\n")
    end,
    K2 = case K#widget.id of
        undefined -> K#widget{id = make_ref(), dest = {0.0,0.0}};
        _ -> K#widget{dest = {0.0,0.0}}
    end,
    {ok, Wd#widget{children = [K2]}, [{ [{id, K2#widget.id}], {resize, Sz} }]};
root_handler({remove_child, Sel}, Wd = #widget{children = Kids}) ->
    {_Deleted, Kept} = lists:partition(fun(K) ->
        selector_matches(K, Sel)
    end, Kids),
    {ok, Wd#widget{children = Kept}, []};
root_handler({resize, NewSize}, Wd = #widget{state = S = #root_state{bgcolor = Bg}, children = Kids}) ->
    {ok, Wd#widget{state = S, size = NewSize, orders = [
        #rect{size = NewSize, color = Bg}
    ]}, [{ [{id, Kid#widget.id}], {resize, NewSize} } || Kid <- Kids]};
root_handler({set_bgcolor, BgColor}, Wd = #widget{size = Size, state = S = #root_state{}}) ->
    S2 = S#root_state{bgcolor = BgColor},
    {ok, Wd#widget{state = S2, orders = [
        #rect{size = Size, color = BgColor}
    ]}, []};
root_handler(Event, Wd) ->
    default_handler(Event, Wd).

-record(hlayout_state, {margin=20, valign=center}).

hlayout_do_layout(Kids, {W, H}, S = #hlayout_state{margin = Margin, valign = VAlign}) ->
    UsedWidth = lists:sum([KW || #widget{size = {KW, KH}} <- Kids]) + Margin * (length(Kids) - 1),
    StartX = W / 2 - UsedWidth / 2,
    {_, NewKids} = lists:foldl(fun(Kid = #widget{size = {KW,KH}}, {X, KKids}) ->
        ThisX = if (X =:= StartX) -> X; true -> X + Margin end,
        ThisY = case VAlign of
            center -> H / 2 - KH / 2;
            top -> Margin;
            bottom -> H - Margin - KH
        end,
        KKid = Kid#widget{dest = {ThisX, ThisY}},
        {ThisX + KW, [KKid | KKids]}
    end, {StartX, []}, Kids),
    lists:reverse(NewKids).

hlayout_handler(init, Wd = #widget{}) ->
    {ok, Wd#widget{state = #hlayout_state{}}, []};
hlayout_handler({set_margin, Margin}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#hlayout_state{margin = Margin},
    NewKids = hlayout_do_layout(Kids, Sz, S2),
    {ok, Wd#widget{children = NewKids, state = S2}, []};
hlayout_handler({set_valign, VAlign}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#hlayout_state{valign = VAlign},
    NewKids = hlayout_do_layout(Kids, Sz, S2),
    {ok, Wd#widget{children = NewKids, state = S2}, []};
hlayout_handler({children_updated, _OldKids}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    NewKids = hlayout_do_layout(Kids, Sz, S),
    {ok, Wd#widget{children = NewKids, state = S}, []};
hlayout_handler({resize, NewSize}, Wd = #widget{state = S, children = Kids}) ->
    NewKids = hlayout_do_layout(Kids, NewSize, S),
    {ok, Wd#widget{children = NewKids, state = S, size = NewSize}, []};
hlayout_handler(Event, Wd) ->
    default_handler(Event, Wd).

-record(vlayout_state, {margin=10, halign=left}).

vlayout_do_layout(Kids, {W, H}, S = #vlayout_state{margin = Margin, halign = HAlign}) ->
    UsedHeight = lists:sum([KH || #widget{size = {KW, KH}} <- Kids]) + Margin * (length(Kids) - 1),
    StartY = H / 2 - UsedHeight / 2,
    {_, NewKids} = lists:foldl(fun(Kid = #widget{size = {KW,KH}}, {Y, KKids}) ->
        ThisY = if (Y =:= StartY) -> Y; true -> Y + Margin end,
        ThisX = case HAlign of
            center -> W / 2 - KW / 2;
            left -> Margin;
            right -> W - Margin - KW
        end,
        KKid = Kid#widget{dest = {ThisX, ThisY}},
        {ThisY + KH, [KKid | KKids]}
    end, {StartY, []}, Kids),
    lists:reverse(NewKids).

vlayout_handler(init, Wd = #widget{}) ->
    {ok, Wd#widget{state = #vlayout_state{}}, []};
vlayout_handler({set_margin, Margin}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#vlayout_state{margin = Margin},
    NewKids = vlayout_do_layout(Kids, Sz, S2),
    {ok, Wd#widget{children = NewKids, state = S2}, []};
vlayout_handler({set_halign, HAlign}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#vlayout_state{halign = HAlign},
    NewKids = vlayout_do_layout(Kids, Sz, S2),
    {ok, Wd#widget{children = NewKids, state = S2}, []};
vlayout_handler({children_updated, _OldKids}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    NewKids = vlayout_do_layout(Kids, Sz, S),
    {ok, Wd#widget{children = NewKids, state = S}, []};
vlayout_handler({resize, NewSize}, Wd = #widget{state = S, children = Kids}) ->
    NewKids = vlayout_do_layout(Kids, NewSize, S),
    {ok, Wd#widget{children = NewKids, state = S, size = NewSize}, []};
vlayout_handler(Event, Wd) ->
    default_handler(Event, Wd).

color_set_order({R, G, B}) ->
    #cairo_set_source_rgba{r = float(R), g = float(G), b = float(B)}.

-record(label_state, {align, text, bgcolor={0,0,0}, fgcolor={1,1,1}}).
label_handler({init, Align, Text}, Wd = #widget{size = Sz}) ->
    label_handler({resize, Sz}, Wd#widget{state = #label_state{align = Align, text = Text}});
label_handler({set_fgcolor, Color}, Wd = #widget{state = S, size = Sz}) ->
    S2 = S#label_state{fgcolor = Color},
    label_handler({resize, Sz}, Wd#widget{state = S2});
label_handler({set_bgcolor, Color}, Wd = #widget{state = S, size = Sz}) ->
    S2 = S#label_state{bgcolor = Color},
    label_handler({resize, Sz}, Wd#widget{state = S2});
label_handler({set_text, Text}, Wd = #widget{state = S, size = Sz}) ->
    S2 = S#label_state{text = Text},
    label_handler({resize, Sz}, Wd#widget{state = S2});
label_handler({resize, {W,H}}, Wd = #widget{state = S}) ->
    #label_state{align = Align, text = Text, bgcolor = Bg, fgcolor = Fg} = S,
    Lines = binary:split(Text, <<"\n">>, [global]),
    NLines = lists:zip(lists:seq(1, length(Lines)), Lines),
    LineH = H / length(Lines),
    Image0 = #cairo_image{width = round(W), height = round(H), data = <<>>},
    {ok, Tags, _} = cairerl_nif:draw(Image0, [], [
        #cairo_select_font_face{family= <<"sans-serif">>},
        #cairo_set_font_size{size = 0.8 * LineH},
        #cairo_font_extents{tag = fontext}] ++
        lists:map(fun({N, Line}) ->
            #cairo_text_extents{text = <<Line/binary, 0>>, tag = {textext, N}}
        end, NLines)),
    LineWs = [{N, LW} || {{textext,N}, #cairo_tag_text_extents{width = LW}} <- Tags],
    NLineW = [{N, proplists:get_value(N, NLines), proplists:get_value(N, LineWs)} || N <- lists:seq(1, length(Lines))],
    #cairo_tag_font_extents{height = FontHeight} = proplists:get_value(fontext, Tags),
    {ok, _, Image1} = cairerl_nif:draw(Image0, [], [
        color_set_order(Bg),
        #cairo_rectangle{width=W,height=H},
        #cairo_fill{},

        color_set_order(Fg),
        #cairo_select_font_face{family= <<"sans-serif">>},
        #cairo_set_font_size{size = 0.8 * LineH}] ++
        lists:flatmap(fun({N, Line, LWidth} = Z) ->
            [#cairo_new_path{},
             #cairo_identity_matrix{}] ++
            case Align of
                center -> [#cairo_translate{x = W/2 - LWidth/2, y = FontHeight * N}];
                left -> [#cairo_translate{y = FontHeight * N}];
                right -> [#cairo_translate{x = W - LWidth, y = FontHeight * N}]
            end ++
            [#cairo_show_text{text = <<Line/binary, 0>>}]
        end, NLineW)),
    {ok, Wd#widget{size = {W,H}, orders = [
        #image{image = Image1}
    ]}, []};
label_handler(Event, Wd) ->
    default_handler(Event, Wd).

-record(button_state, {text}).
button_handler({init, Text}, Wd = #widget{size = Sz}) ->
    button_handler({resize, Sz}, Wd#widget{state = #button_state{text = Text}});
button_handler({set_text, Text}, Wd = #widget{state = S, size = Sz}) ->
    S2 = S#button_state{text = Text},
    button_handler({resize, Sz}, Wd#widget{state = S2});
button_handler(#ts_inpevt_mouse{action = down, buttons = [1]}, Wd = #widget{tags = T, size = Sz}) ->
    case lists:member(mouse_down, T) of
        true -> {ok, Wd, []};
        false -> button_handler({resize, Sz}, Wd#widget{tags = [mouse_down | T]})
    end;
button_handler(#ts_inpevt_mouse{action = up, buttons = [1]}, Wd = #widget{tags = T, size = Sz}) ->
    case lists:member(mouse_down, T) of
        true ->
            {ok, Wd2, Evts} = button_handler({resize, Sz}, Wd#widget{tags = T -- [mouse_down]}),
            {ok, Wd2, Evts ++ [{ ui, {clicked, Wd2#widget.id} }]};
        false -> {ok, Wd, []}
    end;
button_handler(#ts_inpevt_mouse{action = move}, Wd = #widget{tags = T, size = Sz}) ->
    case lists:member(mouse_in, T) of
        true -> {ok, Wd, []};
        false -> button_handler({resize, Sz}, Wd#widget{tags = [mouse_in | T]})
    end;
button_handler(mouse_out, Wd = #widget{tags = T, size = Sz}) ->
    case T of
        [] -> {ok, Wd, []};
        _ -> button_handler({resize, Sz}, Wd#widget{tags = T -- [mouse_in, mouse_down]})
    end;
button_handler({resize, {W,H}}, Wd = #widget{state = S, tags = T}) ->
    MouseIn = lists:member(mouse_in, T),
    MouseDown = lists:member(mouse_down, T),
    IdleBg = {16#78 / 256, 16#1a / 256, 16#97 / 256},
    ActiveBg = {16#99 / 256, 16#2a / 256, 16#c1 /256},
    Fg = {0.95,0.95,1},
    #button_state{text = Text} = S,
    Image0 = #cairo_image{width = round(W), height = round(H), data = <<>>},
    {ok, _, Image1} = cairerl_nif:draw(Image0, [], [
        color_set_order(IdleBg),
        #cairo_rectangle{width=W,height=H},
        #cairo_fill{}] ++
        if MouseIn -> [
            color_set_order(ActiveBg),
            #cairo_translate{x = 2.0, y = 2.0},
            #cairo_rectangle{width = W - 4.0, height = H - 4.0},
            #cairo_fill{}];
        not MouseIn -> []
        end ++ [
        #cairo_identity_matrix{},

        color_set_order(Fg),
        #cairo_select_font_face{family= <<"sans-serif">>},
        #cairo_set_font_size{size = 0.4 * H},
        #cairo_text_extents{text = Text, tag = txte},
        #cairo_tag_deref{tag=txte, field=width, out_tag=txtw},
        #cairo_tag_deref{tag=txte, field=height, out_tag=txth},
        #cairo_translate{x = W / 2, y = H / 2},
        #cairo_scale{x = -0.5, y = 0.5},
        #cairo_translate{x = txtw, y = txth},
        #cairo_scale{x = -2.0, y = 2.0},
        #cairo_show_text{text = Text}
    ]),
    {ok, Wd#widget{size = {W,H}, orders = [
        #image{image = Image1}
    ]}, []};
button_handler(Event, Wd) ->
    default_handler(Event, Wd).

-record(textinput_state, {placeholder, text= <<>>, cursor=0, xs=[0.0], base, mask}).
textinput_get_text(#widget{state = #textinput_state{text = Txt}}) ->
    Txt.

textinput_base(T, {W, H}) ->
    MouseIn = lists:member(mouse_in, T),
    Focus = lists:member(focus, T),
    IdleBg = {0.9, 0.9, 0.9},
    ActiveBg = {1.0, 1.0, 1.0},
    Image0 = #cairo_image{width = round(W), height = round(H), data = <<>>},
    {ok, _, Image1} = cairerl_nif:draw(Image0, [], [
        color_set_order(IdleBg),
        #cairo_rectangle{width=W,height=H},
        #cairo_fill{}] ++
        if MouseIn or Focus -> [
            color_set_order(ActiveBg),
            #cairo_translate{x = 2.0, y = 2.0},
            #cairo_rectangle{width = W - 4.0, height = H - 4.0},
            #cairo_fill{}];
        not MouseIn -> []
        end),
    Image1.

textinput_calc_xs(_SoFar, <<>>, _Sz, _Mask) -> [];
textinput_calc_xs(SoFar, <<Next,Rest/binary>>, Sz = {W, H}, Mask) ->
    Image0 = #cairo_image{width = round(W), height = round(H), data = <<>>},
    Text = <<SoFar/binary, Next>>,
    MaskedText = case Mask of
        undefined -> <<Text/binary, 0>>;
        _ -> M = binary:copy(Mask, byte_size(SoFar) + 1), <<M/binary, 0>>
    end,
    {ok, Tags, _} = cairerl_nif:draw(Image0, [], [
        #cairo_select_font_face{family= <<"sans-serif">>},
        #cairo_set_font_size{size = 0.5 * H},
        #cairo_text_extents{text = MaskedText, tag = txte}
        ]),
    #cairo_tag_text_extents{x_advance = XAdv} = proplists:get_value(txte, Tags),
    [XAdv | textinput_calc_xs(<<SoFar/binary, Next>>, Rest, Sz, Mask)].

textinput_handler({init, Placeholder}, Wd = #widget{}) ->
    textinput_handler(redraw_base,
        Wd#widget{tags = [focusable], state = #textinput_state{placeholder = Placeholder}});
textinput_handler({init, Placeholder, Mask}, Wd = #widget{}) ->
    textinput_handler(redraw_base,
        Wd#widget{tags = [focusable], state = #textinput_state{placeholder = Placeholder, mask = Mask}});
textinput_handler(#ts_inpevt_key{code = shift, action = down}, Wd = #widget{tags = T}) ->
    case lists:member(shift_held, T) of
        true -> {ok, Wd, []};
        false -> {ok, Wd#widget{tags = [shift_held | T]}, []}
    end;
textinput_handler(#ts_inpevt_key{code = shift, action = up}, Wd = #widget{tags = T}) ->
    case lists:member(shift_held, T) of
        true -> {ok, Wd#widget{tags = T -- [shift_held]}, []};
        false -> {ok, Wd, []}
    end;
textinput_handler(#ts_inpevt_key{code = left, action = down}, Wd = #widget{state = S}) ->
    #textinput_state{cursor = Cursor0} = S,
    case Cursor0 of
        N when N > 0 ->
            Cursor1 = Cursor0 - 1,
            S2 = S#textinput_state{cursor = Cursor1},
            textinput_handler(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;
textinput_handler(#ts_inpevt_key{code = home, action = down}, Wd = #widget{state = S}) ->
    S2 = S#textinput_state{cursor = 0},
    textinput_handler(redraw_text, Wd#widget{state = S2});
textinput_handler(#ts_inpevt_key{code = 'end', action = down}, Wd = #widget{state = S}) ->
    #textinput_state{text = Text} = S,
    TextLen = byte_size(Text),
    S2 = S#textinput_state{cursor = TextLen},
    textinput_handler(redraw_text, Wd#widget{state = S2});
textinput_handler(#ts_inpevt_key{code = right, action = down}, Wd = #widget{state = S}) ->
    #textinput_state{cursor = Cursor0, text = Text} = S,
    TextLen = byte_size(Text),
    case Cursor0 of
        N when N < TextLen ->
            Cursor1 = Cursor0 + 1,
            S2 = S#textinput_state{cursor = Cursor1},
            textinput_handler(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;
textinput_handler(#ts_inpevt_key{code = bksp, action = down}, Wd = #widget{state = S}) ->
    #textinput_state{xs = Xs0, text = Text0, cursor = Cursor0, mask = M} = S,
    case Cursor0 of
        N when N > 0 ->
            TextBefore = binary:part(Text0, {0, Cursor0-1}),
            XsBefore = lists:sublist(Xs0, Cursor0),
            TextAfter = binary:part(Text0, {Cursor0, byte_size(Text0) - Cursor0}),
            Xs1 = XsBefore ++ textinput_calc_xs(TextBefore, TextAfter, Wd#widget.size, M),
            Text1 = <<TextBefore/binary, TextAfter/binary>>,
            Cursor1 = Cursor0 - 1,
            S2 = S#textinput_state{xs = Xs1, text = Text1, cursor = Cursor1},
            textinput_handler(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;
textinput_handler(#ts_inpevt_key{code = del, action = down}, Wd = #widget{state = S}) ->
    #textinput_state{xs = Xs0, text = Text0, cursor = Cursor0, mask = M} = S,
    TextLen = byte_size(Text0),
    case Cursor0 of
        N when N < TextLen ->
            TextBefore = binary:part(Text0, {0, Cursor0}),
            XsBefore = lists:sublist(Xs0, Cursor0 + 1),
            TextAfter = binary:part(Text0, {Cursor0 + 1, byte_size(Text0) - (Cursor0 + 1)}),
            Xs1 = XsBefore ++ textinput_calc_xs(TextBefore, TextAfter, Wd#widget.size, M),
            Text1 = <<TextBefore/binary, TextAfter/binary>>,
            S2 = S#textinput_state{xs = Xs1, text = Text1},
            textinput_handler(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;
textinput_handler(#ts_inpevt_key{code = enter, action = down}, Wd = #widget{id = Id}) ->
    {ok, Wd, [{ui, {submitted, Id}}]};
textinput_handler(E = #ts_inpevt_key{code = space}, Wd = #widget{}) ->
    textinput_handler(E#ts_inpevt_key{code = {32, 32}}, Wd);
textinput_handler(#ts_inpevt_key{code = {Unshift, Shift}, action = down}, Wd = #widget{tags = T, state = S}) ->
    Char = case lists:member(shift_held, T) of
        true -> Shift;
        false -> Unshift
    end,

    #textinput_state{xs = Xs0, text = Text0, cursor = Cursor0, mask = M} = S,
    TextBefore = binary:part(Text0, {0, Cursor0}),
    XsBefore = lists:sublist(Xs0, Cursor0 + 1),

    TextAfter0 = binary:part(Text0, {Cursor0, byte_size(Text0) - Cursor0}),
    TextAfter1 = <<Char, TextAfter0/binary>>,

    Xs1 = XsBefore ++ textinput_calc_xs(TextBefore, TextAfter1, Wd#widget.size, M),
    Text1 = <<TextBefore/binary, TextAfter1/binary>>,
    Cursor1 = Cursor0 + 1,

    S2 = S#textinput_state{xs = Xs1, text = Text1, cursor = Cursor1},
    textinput_handler(redraw_text, Wd#widget{state = S2});
textinput_handler(focus, Wd = #widget{tags = T, state = S}) ->
    #textinput_state{text = Text} = S,
    TextLen = byte_size(Text),
    S2 = S#textinput_state{cursor = TextLen},
    case lists:member(focus, T) of
        true -> {ok, Wd, []};
        false ->
            textinput_handler(redraw_base, Wd#widget{state = S2, tags = [focus | T]})
    end;
textinput_handler(#ts_inpevt_mouse{action = down, buttons = [1], point = {X,Y}}, Wd = #widget{tags = T, size = {W,H}, state = S}) ->
    YFrac = Y / H,
    #textinput_state{xs = Xs} = S,
    S2 = if
        (YFrac > 0.1) andalso (YFrac < 0.9) ->
            NewCursor = length(lists:takewhile(fun(XX) -> XX < X end, Xs)) - 1,
            S#textinput_state{cursor = NewCursor};
        true -> S
    end,
    case lists:member(focus, T) of
        true ->
            textinput_handler(redraw_text, Wd#widget{state = S2});
        false ->
            textinput_handler(redraw_base, Wd#widget{state = S2, tags = [focus | T]})
    end;
textinput_handler(#ts_inpevt_mouse{action = move}, Wd = #widget{tags = T}) ->
    case lists:member(mouse_in, T) of
        true -> {ok, Wd, []};
        false -> textinput_handler(redraw_base, Wd#widget{tags = [mouse_in | T]})
    end;
textinput_handler(mouse_out, Wd = #widget{tags = T}) ->
    case lists:member(mouse_in, T) of
        false -> {ok, Wd, []};
        _ -> textinput_handler(redraw_base, Wd#widget{tags = T -- [mouse_in]})
    end;
textinput_handler(blur, Wd = #widget{tags = T}) ->
    case lists:member(focus, T) of
        false -> {ok, Wd, []};
        _ -> textinput_handler(redraw_base, Wd#widget{tags = T -- [focus]})
    end;
textinput_handler({resize, {W,H}}, Wd = #widget{state = S, tags = T}) ->
    textinput_handler(redraw_base, Wd#widget{size = {W,H}});
textinput_handler(redraw_base, Wd = #widget{state = S, tags = T, size = Sz}) ->
    Img = textinput_base(T, Sz),
    S2 = S#textinput_state{base = Img},
    textinput_handler(redraw_text, Wd#widget{state = S2});
textinput_handler(redraw_text, Wd = #widget{state = S, tags = T, size = {W, H}}) ->
    #textinput_state{text = Text, cursor = N, xs = Xs, base = Image0, placeholder = Placeholder, mask = Mask} = S,
    TextBefore = binary:part(Text, {0, N}),
    TextAfter = binary:part(Text, {N, byte_size(Text) - N}),
    TextBeforeMasked = case Mask of
        undefined -> TextBefore;
        _ -> binary:copy(Mask, byte_size(TextBefore))
    end,
    TextAfterMasked = case Mask of
        undefined -> TextAfter;
        _ -> binary:copy(Mask, byte_size(TextAfter))
    end,
    CursorX = lists:nth(N + 1, Xs),
    Focus = lists:member(focus, T),
    Fg = {0.0,0.0,0.0},
    FgPlaceHolder = {0.6, 0.6, 0.6},
    FgPlaceHolder2 = {0.7, 0.7, 0.7},
    {ok, _, Image1} = case Text of
        <<>> when (not Focus) ->
            cairerl_nif:draw(Image0, [], [
                color_set_order(FgPlaceHolder),
                #cairo_select_font_face{family= <<"sans-serif">>},
                #cairo_set_font_size{size = 0.5 * H},

                #cairo_translate{x = 5.0, y = 0.7*H},
                #cairo_show_text{text = <<Placeholder/binary, 0>>}
            ]);
        <<>> ->
            cairerl_nif:draw(Image0, [], [
                #cairo_select_font_face{family= <<"sans-serif">>},
                #cairo_set_font_size{size = 0.5 * H},

                #cairo_translate{x = 5.0, y = 0.7*H},
                color_set_order(Fg),
                #cairo_set_line_width{width = 1.5},
                #cairo_move_to{x = 0.0, y = 0.1*H},
                #cairo_line_to{flags = [relative], y = -0.6*H},
                #cairo_stroke{},
                color_set_order(FgPlaceHolder2),
                #cairo_show_text{text = <<Placeholder/binary, 0>>}
            ]);
        _ ->
            cairerl_nif:draw(Image0, [], [
                color_set_order(Fg),
                #cairo_select_font_face{family= <<"sans-serif">>},
                #cairo_set_font_size{size = 0.5 * H},

                #cairo_translate{x = 5.0, y = 0.7*H},
                #cairo_show_text{text = <<TextBeforeMasked/binary, 0>>},

                #cairo_translate{x = CursorX},
                #cairo_show_text{text = <<TextAfterMasked/binary, 0>>}] ++
                if Focus -> [
                    #cairo_set_line_width{width = 1.5},
                    #cairo_move_to{x = 0.0, y = 0.1*H},
                    #cairo_line_to{flags = [relative], y = -0.6*H},
                    #cairo_stroke{}];
                not Focus -> [] end ++ [
            ])
    end,
    {ok, Wd#widget{orders = [
        #image{image = Image1}
    ]}, []};
textinput_handler(Event, Wd) ->
    default_handler(Event, Wd).

png_image_handler({init, Fn}, Wd = #widget{}) ->
    {ok, Png} = cairerl_nif:png_read(Fn),
    #cairo_image{width = W, height = H} = Png,
    Image0 = #cairo_image{width=W, height=H, data = <<>>},
    {ok, _, Image1} = cairerl_nif:draw(Image0, [], [
        #cairo_pattern_create_for_surface{tag=png, image=Png},
        #cairo_set_source{tag=png},
        #cairo_rectangle{x=0.0,y=0.0,width=float(W),height=float(H)},
        #cairo_fill{}
        ]),
    {ok, Wd#widget{size = {W, H}, orders = [
        #image{image = Image1}
    ]}, []};
png_image_handler(Event, Wd) ->
    default_handler(Event, Wd).
