%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_vlayout).
-include_lib("rdp_proto/include/rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([handle/2]).

-record(state, {margin=10, halign=left}).

do_layout(Kids, {W, H}, S = #state{margin = Margin, halign = HAlign}) ->
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

handle(init, Wd = #widget{}) ->
    {ok, Wd#widget{state = #state{}}, []};

handle({set_margin, Margin}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#state{margin = Margin},
    NewKids = do_layout(Kids, Sz, S2),
    {ok, Wd#widget{children = NewKids, orders = [#null_order{}], state = S2}, []};

handle({set_halign, HAlign}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#state{halign = HAlign},
    NewKids = do_layout(Kids, Sz, S2),
    {ok, Wd#widget{children = NewKids, orders = [#null_order{}], state = S2}, []};

handle({children_updated, _OldKids}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    NewKids = do_layout(Kids, Sz, S),
    case NewKids of
        Kids -> {ok, Wd, []};
        _ -> {ok, Wd#widget{children = NewKids, orders = [#null_order{}]}, []}
    end;

handle({resize, NewSize}, Wd = #widget{state = S, children = Kids}) ->
    NewKids = do_layout(Kids, NewSize, S),
    {ok, Wd#widget{children = NewKids, state = S, size = NewSize, orders = [#null_order{}]}, []};

handle(Event, Wd) ->
    ui:default_handler(Event, Wd).
