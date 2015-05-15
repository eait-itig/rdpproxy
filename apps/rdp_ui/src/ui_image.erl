%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_image).
-include_lib("rdp_proto/include/rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([handle/2]).

handle({init, Fn}, Wd = #widget{format = F}) ->
    {ok, Png} = cairerl_nif:png_read(Fn),
    #cairo_image{width = W, height = H} = Png,
    Image0 = #cairo_image{width=W, height=H, format = F, data = <<>>},
    {ok, _, Image1} = cairerl_nif:draw(Image0, [], [
        #cairo_pattern_create_for_surface{tag=png, image=Png},
        #cairo_set_source{tag=png},
        #cairo_rectangle{x=0.0,y=0.0,width=float(W),height=float(H)},
        #cairo_fill{}
        ]),
    {ok, Wd#widget{size = {W, H}, orders = [
        #image{image = Image1}
    ]}, []};

handle(Event, Wd) ->
    ui:default_handler(Event, Wd).
