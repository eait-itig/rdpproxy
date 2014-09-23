%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_hlayout).
-include_lib("rdp_proto/include/rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([handle/2]).

-record(state, {margin=20, valign=center}).

do_layout(Kids, {W, H}, S = #state{margin = Margin, valign = VAlign}) ->
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

handle(init, Wd = #widget{}) ->
    {ok, Wd#widget{state = #state{}}, []};

handle({set_margin, Margin}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#state{margin = Margin},
    NewKids = do_layout(Kids, Sz, S2),
    {ok, Wd#widget{children = NewKids, orders = [#null_order{}], state = S2}, []};

handle({set_valign, VAlign}, Wd = #widget{state = S, size = Sz, children = Kids}) ->
    S2 = S#state{valign = VAlign},
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
