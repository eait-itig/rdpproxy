%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_root).
-include_lib("rdp_proto/include/rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([handle/2]).

-record(state, {bgcolor = {0,0,0}, focus=[]}).

handle(init, Wd = #widget{size = Sz}) ->
    State = #state{},
    {ok, Wd#widget{state = State, orders = [
        #rect{size = Sz, color = State#state.bgcolor}
    ]}, []};

handle(focus_next, Wd = #widget{state = S}) ->
    #state{focus = Focus} = S,
    Focusable = ui:select(Wd, [{tag, focusable}]),
    ToFocus = case lists:dropwhile(fun(K) -> not lists:member(K#widget.id, Focus) end, Focusable) of
        [_InFocus, Next | _Rest] -> Next;
        _ -> [Next | _] = Focusable, Next
    end,
    NewIds = [ToFocus#widget.id],
    FocusEvts = [{ [{id, Id}], focus } || Id <- NewIds],
    {ok, Wd, FocusEvts};

handle({children_updated, _OldKids}, Wd = #widget{children = NewKids, state = S = #state{focus = OldFocus}}) ->
    NewFocus = ui:select(Wd, [{tag, focus}]),
    case [K#widget.id || K <- NewFocus] of
        OldFocus ->
            {ok, Wd, []};
        AllNewIds ->
            NewIds = AllNewIds -- OldFocus,
            UnfocusEvts = [{ [{id, Id}], blur } || Id <- OldFocus],
            S2 = S#state{focus = NewIds},
            {ok, Wd#widget{state = S2}, UnfocusEvts}
    end;

handle({add_child, K}, Wd = #widget{children = Kids, size = Sz}) ->
    case Kids of
        [] -> ok;
        _ -> lager:warning("root widget replacing child")
    end,
    K2 = case K#widget.id of
        undefined -> K#widget{id = make_ref(), dest = {0.0,0.0}};
        _ -> K#widget{dest = {0.0,0.0}}
    end,
    {ok, Wd#widget{children = [K2]}, [{ [{id, K2#widget.id}], {resize, Sz} }]};

handle({remove_child, Sel}, Wd = #widget{children = Kids}) ->
    {_Deleted, Kept} = lists:partition(fun(K) ->
        ui:selector_matches(K, Sel)
    end, Kids),
    {ok, Wd#widget{children = Kept}, []};

handle({resize, NewSize}, Wd = #widget{state = S = #state{bgcolor = Bg}, children = Kids}) ->
    {ok, Wd#widget{state = S, size = NewSize, orders = [
        #rect{size = NewSize, color = Bg}
    ]}, [{ [{id, Kid#widget.id}], {resize, NewSize} } || Kid <- Kids]};

handle({set_bgcolor, BgColor}, Wd = #widget{size = Size, state = S = #state{}}) ->
    S2 = S#state{bgcolor = BgColor},
    {ok, Wd#widget{state = S2, orders = [
        #rect{size = Size, color = BgColor}
    ]}, []};

handle(Event, Wd) ->
    ui:default_handler(Event, Wd).
