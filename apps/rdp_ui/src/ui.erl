%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui).
-include_lib("rdp_proto/include/rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([new/1, handle_events/2, select/2, print/1]).
-export([default_handler/2, selector_matches/2]).
-export([divide_bitmap/1, divide_bitmap/2, orders_to_updates/1, dedupe_orders/1]).

-spec new(Size :: size()) -> {widget(), [order()]}.
new(Size) ->
    Root = #widget{id = root, mod = ui_root, size = Size, dest = {0.0, 0.0}},
    handle_events(Root, [{ [{id, root}], init }]).

-type selector() :: {id, term()} |
                    {contains, point()} |
                    {mod, atom()} |
                    {tag, atom()}.

-spec rect_contains(Dest :: point(), Size :: size(), Point :: point()) -> boolean().
rect_contains({X0, Y0}, {W, H}, {X, Y}) ->
    (X >= X0) andalso (Y >= Y0) andalso
    (X =< X0 + W) andalso (Y =< Y0 + H).

-spec selector_matches(widget(), selector()) -> boolean().
selector_matches(W, {id, Id}) -> W#widget.id =:= Id;
selector_matches(W, {mod, H}) -> W#widget.mod =:= H;
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
    [I#image{dest = {X0 + X, Y0 + Y}} | offset_orders(O, Rest)];
offset_orders(O, [N = #null_order{} | Rest]) ->
    [N | offset_orders(O, Rest)].

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
print(#widget{dest = D, size = S, mod = M, id = Id, children = Kids}, Indent) ->
    io:format("~s#widget{id = ~p, dest = ~p, size = ~p, mod = ~p}\n", [Indent, Id, D, S, M]),
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

handle(W = #widget{mod = M, children = [], orders = OldOrders}, [{contains, Pt}], Event) ->
    case selector_matches(W, {contains, Pt}) of
        true ->
            case M:handle(Event, W) of
                {ok, W2 = #widget{orders = OldOrders, children = []}, MoreEvts} ->
                    {W2, [], MoreEvts};
                {ok, W2 = #widget{orders = Orders}, MoreEvts} ->
                    {W2, Orders, MoreEvts}
            end;
        false ->
            {W, [], []}
    end;
handle(W = #widget{mod = M, orders = OldOrders, children = Kids}, [Selector = {Type, _}], Event) ->
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
            case M:handle(Event, W) of
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
handle(W = #widget{dest = D, children = K, mod = M}, [Selector = {Type, _} | SelRest], Event) ->
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

handle_recurse(W = #widget{dest = D, mod = M, orders = OldOrders, children = Kids}, NewKOs) ->
    NewKids = [K || {K, O, Es} <- NewKOs],
    Evts = lists:flatmap(fun({K, O, Es}) -> Es end, NewKOs),
    W2 = W#widget{children = NewKids},
    case lists:any(fun({_, [], _}) -> false; ({_, _, _}) -> true end, NewKOs) of
        false ->
            {W2, [], Evts};
        true ->
            case M:handle({children_updated, Kids}, W2) of
                {ok, W3 = #widget{orders = OldOrders, children = NewKids}, MoreEvts} ->
                    Orders = lists:flatmap(fun({K = #widget{dest = KD}, O, _Es}) ->
                        offset_orders(K#widget.dest, O)
                    end, NewKOs),
                    case Orders of
                        [#null_order{} | _] ->
                            {W3, collect_orders(W3), Evts ++ MoreEvts};
                        _ ->
                            {W3, Orders, Evts ++ MoreEvts}
                    end;
                {ok, W3 = #widget{}, MoreEvts} ->
                    {W3, collect_orders(W3), Evts ++ MoreEvts}
            end
    end.

% default handler for widget implementations to use

default_handler({children_updated, _OldKids}, Wd = #widget{}) ->
    {ok, Wd, []};
default_handler({add_child, K}, Wd = #widget{children = Kids}) ->
    K2 = case K#widget.id of
        undefined -> K#widget{id = make_ref()};
        _ -> K
    end,
    {ok, Wd#widget{children = Kids ++ [K2]}, []};
default_handler({add_child, {before, Sel}, K}, Wd = #widget{children = Kids}) ->
    K2 = case K#widget.id of
        undefined -> K#widget{id = make_ref()};
        _ -> K
    end,
    {BeforeNew, AfterNew} = lists:splitwith(fun(Kid) -> not selector_matches(Kid, Sel) end, Kids),
    {ok, Wd#widget{children = BeforeNew ++ [K2 | AfterNew]}, []};
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
default_handler(Event, Wd = #widget{id = Id, mod = M}) ->
    lager:debug("<widget ~p (~p)> ignored event ~p", [Id, M, Event]),
    {ok, Wd, []}.

% ts utils

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

-define(BITMAP_SLICE_TGT, (4000 div 4)).

divide_bitmap(I = #cairo_image{}) ->
    divide_bitmap(I, {0,0}).
divide_bitmap(I = #cairo_image{width = W, height = H}, {X0,Y0})
        when (X0 < 0); (Y0 < 0) ->
    X = lists:max([X0, 0]),
    Y = lists:max([Y0, 0]),
    [{X, Y, Slice}] = slice_bitmap(I, [X, W], [Y, H]),
    divide_bitmap(Slice, {X, Y});
divide_bitmap(I = #cairo_image{width = W, height = H}, {X0,Y0})
        when (W * H > 4 * ?BITMAP_SLICE_TGT) ->
    XInt = lists:max([4, 4 * (round(math:sqrt(W / H * ?BITMAP_SLICE_TGT)) div 4)]),
    YInt = lists:max([4, 4 * (round(math:sqrt(H / W * ?BITMAP_SLICE_TGT)) div 4)]),
    XIntervals = lists:seq(0, W-4, XInt) ++ [W],
    YIntervals = lists:seq(0, H-4, YInt) ++ [H],
    Slices = slice_bitmap(I, XIntervals, YIntervals),
    lists:flatmap(fun({X, Y, Slice}) ->
        divide_bitmap(Slice, {X0 + X, Y0 + Y})
    end, Slices);
divide_bitmap(I = #cairo_image{data = D, width = W, height = H}, {X,Y}) ->
    ShouldBeSize = W * H * 4,
    ShouldBeSize = byte_size(D),
    {ok, Compr} = rle_nif:compress(D, W, H),
    CompInfo = #ts_bitmap_comp_info{
        flags = [compressed]},
        %full_size = byte_size(D),
        %scan_width = W},
    true = (byte_size(Compr) < 1 bsl 16),
    [#ts_bitmap{dest={X,Y}, size={W,H}, bpp=24, data = Compr,
        comp_info = CompInfo}].

rect_to_ts_order(#rect{dest={X,Y}, size={W,H}, color={R,G,B}}) ->
    #ts_order_opaquerect{dest={round(X),round(Y)},
        size={round(W),round(H)},
        color={round(R*256), round(G*256), round(B*256)}}.

dedupe_orders(L) ->
    dedupe_orders(lists:reverse(L), [], gb_sets:new()).

dedupe_orders([], SoFar, _) -> SoFar;
dedupe_orders([O = #rect{dest = {X,Y}, size = {W,H}} | Rest], SoFar, Set) ->
    case gb_sets:is_element({X,Y,W,H}, Set) of
        true -> dedupe_orders(Rest, SoFar, Set);
        false -> dedupe_orders(Rest, [O | SoFar], gb_sets:add_element({X,Y,W,H}, Set))
    end;
dedupe_orders([O = #image{dest = {X,Y}, image = #cairo_image{width=W, height=H}} | Rest], SoFar, Set) ->
    case gb_sets:is_element({X,Y,W,H}, Set) of
        true -> dedupe_orders(Rest, SoFar, Set);
        false -> dedupe_orders(Rest, [O | SoFar], gb_sets:add_element({X,Y,W,H}, Set))
    end;
dedupe_orders([O = #null_order{} | Rest], SoFar, Set) ->
    dedupe_orders(Rest, [O | SoFar], Set).

orders_to_updates([]) -> [];
orders_to_updates(L = [#rect{} | _]) ->
    {Rects, Rest} = lists:splitwith(fun(#rect{}) -> true; (_) -> false end, L),
    [#ts_update_orders{orders = lists:map(fun rect_to_ts_order/1, Rects)} |
        orders_to_updates(Rest)];
orders_to_updates([#image{dest = {X,Y}, image = Im} | Rest]) ->
    Bitmaps = divide_bitmap(Im, {round(X), round(Y)}),
    Orders = bitmaps_to_orders(Bitmaps),
    Orders ++ orders_to_updates(Rest);
orders_to_updates([#null_order{} | Rest]) ->
    orders_to_updates(Rest).

bitmaps_to_orders(Bms) ->
    lists:reverse(bitmaps_to_orders(0, [], Bms)).

bitmaps_to_orders(_, [], []) -> [];
bitmaps_to_orders(_, R, []) ->
    [#ts_update_bitmaps{bitmaps = lists:reverse(R)}];
bitmaps_to_orders(Size, R, [Next | Rest]) ->
    #ts_bitmap{data = D} = Next,
    NewSize = Size + byte_size(D),
    if
        (NewSize > 16000) or (length(R) > 16) ->
            [#ts_update_bitmaps{bitmaps = lists:reverse(R)} |
                bitmaps_to_orders(0, [Next], Rest)];
        true ->
            bitmaps_to_orders(NewSize, [Next | R], Rest)
    end.
