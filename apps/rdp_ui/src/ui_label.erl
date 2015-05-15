%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_label).
-include_lib("rdp_proto/include/rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([handle/2, get_text/1]).

color_set_order({R, G, B}) ->
    #cairo_set_source_rgba{r = float(R), g = float(G), b = float(B)}.

-record(state, {align, text, bgcolor={0,0,0}, fgcolor={1,1,1}}).

get_text(Wd = #widget{state = #state{text = Text}}) ->
    Text.

handle({init, Align, Text}, Wd = #widget{size = Sz}) ->
    handle({resize, Sz}, Wd#widget{state = #state{align = Align, text = Text}});

handle({set_fgcolor, Color}, Wd = #widget{state = S, size = Sz}) ->
    S2 = S#state{fgcolor = Color},
    handle({resize, Sz}, Wd#widget{state = S2});

handle({set_bgcolor, Color}, Wd = #widget{state = S, size = Sz}) ->
    S2 = S#state{bgcolor = Color},
    handle({resize, Sz}, Wd#widget{state = S2});

handle({set_text, Text}, Wd = #widget{state = S, size = Sz}) ->
    S2 = S#state{text = Text},
    handle({resize, Sz}, Wd#widget{state = S2});

handle({resize, {W,H}}, Wd = #widget{state = S, format = F}) ->
    #state{align = Align, text = Text, bgcolor = Bg, fgcolor = Fg} = S,
    Lines = binary:split(Text, <<"\n">>, [global]),
    NLines = lists:zip(lists:seq(1, length(Lines)), Lines),
    LineH = H / length(Lines),
    Image0 = #cairo_image{width = round(W), height = round(H),
        format = F, data = <<>>},
    {ok, Tags, _} = cairerl_nif:draw(Image0, [], [
        #cairo_select_font_face{family= <<"sans-serif">>},
        #cairo_set_font_size{size = 0.8 * LineH},
        #cairo_font_extents{tag = fontext}] ++
        lists:map(fun({N, Line}) ->
            #cairo_text_extents{text = <<Line/binary, 0>>, tag = {textext, N}}
        end, NLines)),
    LineWs = [{N, LW} || {{textext,N}, #cairo_tag_text_extents{width = LW}} <- Tags],
    NLineW = [{N, proplists:get_value(N, NLines), proplists:get_value(N, LineWs)} || N <- lists:seq(1, length(Lines))],
    #cairo_tag_font_extents{height = FontHeight, descent = FontDescent} = proplists:get_value(fontext, Tags),
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
                center -> [#cairo_translate{x = W/2 - LWidth/2, y = FontHeight * N - FontDescent}];
                left -> [#cairo_translate{y = FontHeight * N - FontDescent}];
                right -> [#cairo_translate{x = W - LWidth, y = FontHeight * N - FontDescent}]
            end ++
            [#cairo_show_text{text = <<Line/binary, 0>>}]
        end, NLineW)),
    {ok, Wd#widget{size = {W,H}, orders = [
        #image{image = Image1}
    ]}, []};

handle(Event, Wd) ->
    ui:default_handler(Event, Wd).
