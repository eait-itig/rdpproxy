%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(ui_textinput).
-include_lib("rdp_proto/include/rdpp.hrl").
-include("ui.hrl").
-include_lib("cairerl/include/cairerl.hrl").

-export([handle/2, get_text/1]).

color_set_order({R, G, B}) ->
    #cairo_set_source_rgba{r = float(R), g = float(G), b = float(B)}.

-record(state, {placeholder, text= <<>>, cursor=0, xs=[0.0], base, mask}).
get_text(#widget{state = #state{text = Txt}}) ->
    Txt.

base(T, {W, H}, F) ->
    MouseIn = lists:member(mouse_in, T),
    Focus = lists:member(focus, T),
    IdleBg = {0.9, 0.9, 0.9},
    ActiveBg = {1.0, 1.0, 1.0},
    Image0 = #cairo_image{width = round(W), height = round(H),
        format = F, data = <<>>},
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

calc_xs(_SoFar, <<>>, _Sz, _Mask) -> [];
calc_xs(SoFar, <<Next,Rest/binary>>, Sz = {W, H}, Mask) ->
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
    [XAdv | calc_xs(<<SoFar/binary, Next>>, Rest, Sz, Mask)].

handle({init, Placeholder}, Wd = #widget{}) ->
    handle(redraw_base,
        Wd#widget{tags = [focusable], state = #state{placeholder = Placeholder}});

handle({init, Placeholder, Mask}, Wd = #widget{}) ->
    handle(redraw_base,
        Wd#widget{tags = [focusable], state = #state{placeholder = Placeholder, mask = Mask}});

handle({set_text, Text}, Wd = #widget{state = S}) ->
    #state{mask = M} = S,
    Xs = calc_xs(<<>>, Text, Wd#widget.size, M),
    S2 = S#state{text = Text, cursor = byte_size(Text), xs = [0.0 | Xs]},
    handle(redraw_text, Wd#widget{state = S2});

handle(#ts_inpevt_key{code = shift, action = down}, Wd = #widget{tags = T}) ->
    case lists:member(shift_held, T) of
        true -> {ok, Wd, []};
        false -> {ok, Wd#widget{tags = [shift_held | T]}, []}
    end;

handle(#ts_inpevt_key{code = shift, action = up}, Wd = #widget{tags = T}) ->
    case lists:member(shift_held, T) of
        true -> {ok, Wd#widget{tags = T -- [shift_held]}, []};
        false -> {ok, Wd, []}
    end;

handle(#ts_inpevt_key{code = left, action = down}, Wd = #widget{state = S}) ->
    #state{cursor = Cursor0} = S,
    case Cursor0 of
        N when N > 0 ->
            Cursor1 = Cursor0 - 1,
            S2 = S#state{cursor = Cursor1},
            handle(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;

handle(#ts_inpevt_key{code = home, action = down}, Wd = #widget{state = S}) ->
    S2 = S#state{cursor = 0},
    handle(redraw_text, Wd#widget{state = S2});

handle(#ts_inpevt_key{code = 'end', action = down}, Wd = #widget{state = S}) ->
    #state{text = Text} = S,
    TextLen = byte_size(Text),
    S2 = S#state{cursor = TextLen},
    handle(redraw_text, Wd#widget{state = S2});

handle(#ts_inpevt_key{code = right, action = down}, Wd = #widget{state = S}) ->
    #state{cursor = Cursor0, text = Text} = S,
    TextLen = byte_size(Text),
    case Cursor0 of
        N when N < TextLen ->
            Cursor1 = Cursor0 + 1,
            S2 = S#state{cursor = Cursor1},
            handle(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;

handle(#ts_inpevt_key{code = bksp, action = down}, Wd = #widget{state = S}) ->
    #state{xs = Xs0, text = Text0, cursor = Cursor0, mask = M} = S,
    case Cursor0 of
        N when N > 0 ->
            TextBefore = binary:part(Text0, {0, Cursor0-1}),
            XsBefore = lists:sublist(Xs0, Cursor0),
            TextAfter = binary:part(Text0, {Cursor0, byte_size(Text0) - Cursor0}),
            Xs1 = XsBefore ++ calc_xs(TextBefore, TextAfter, Wd#widget.size, M),
            Text1 = <<TextBefore/binary, TextAfter/binary>>,
            Cursor1 = Cursor0 - 1,
            S2 = S#state{xs = Xs1, text = Text1, cursor = Cursor1},
            handle(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;

handle(#ts_inpevt_key{code = del, action = down}, Wd = #widget{state = S}) ->
    #state{xs = Xs0, text = Text0, cursor = Cursor0, mask = M} = S,
    TextLen = byte_size(Text0),
    case Cursor0 of
        N when N < TextLen ->
            TextBefore = binary:part(Text0, {0, Cursor0}),
            XsBefore = lists:sublist(Xs0, Cursor0 + 1),
            TextAfter = binary:part(Text0, {Cursor0 + 1, byte_size(Text0) - (Cursor0 + 1)}),
            Xs1 = XsBefore ++ calc_xs(TextBefore, TextAfter, Wd#widget.size, M),
            Text1 = <<TextBefore/binary, TextAfter/binary>>,
            S2 = S#state{xs = Xs1, text = Text1},
            handle(redraw_text, Wd#widget{state = S2});
        _ ->
            {ok, Wd, []}
    end;

handle(#ts_inpevt_key{code = caps, action = down}, Wd = #widget{tags = T}) ->
    case lists:member(capslock, T) of
        true -> {ok, Wd#widget{tags = T -- [capslock]}, []};
        false -> {ok, Wd#widget{tags = [capslock | T]}, []}
    end;

handle(#ts_inpevt_sync{flags = F}, Wd = #widget{tags = T}) ->
    case lists:member(capslock, F) of
        false -> {ok, Wd#widget{tags = T -- [capslock]}, []};
        true ->
            case lists:member(capslock, T) of
                true -> {ok, Wd, []};
                false -> {ok, Wd#widget{tags = [capslock | T]}, []}
            end
    end;

handle(#ts_inpevt_key{code = enter, action = down}, Wd = #widget{id = Id}) ->
    {ok, Wd, [{ui, {submitted, Id}}]};

handle(E = #ts_inpevt_key{code = space}, Wd = #widget{}) ->
    handle(E#ts_inpevt_key{code = {32, 32}}, Wd);

handle(#ts_inpevt_unicode{code = Codepoint, action = down}, Wd = #widget{tags = T, state = S}) ->
    Char = unicode:characters_to_binary([Codepoint], {utf16, little}, utf8),

    #state{xs = Xs0, text = Text0, cursor = Cursor0, mask = M} = S,
    TextBefore = binary:part(Text0, {0, Cursor0}),
    XsBefore = lists:sublist(Xs0, Cursor0 + 1),

    TextAfter0 = binary:part(Text0, {Cursor0, byte_size(Text0) - Cursor0}),
    TextAfter1 = <<Char/binary, TextAfter0/binary>>,

    Xs1 = XsBefore ++ calc_xs(TextBefore, TextAfter1, Wd#widget.size, M),
    Text1 = <<TextBefore/binary, TextAfter1/binary>>,
    Cursor1 = Cursor0 + 1,

    S2 = S#state{xs = Xs1, text = Text1, cursor = Cursor1},
    handle(redraw_text, Wd#widget{state = S2});

handle(#ts_inpevt_key{code = {Unshift, Shift}, action = down}, Wd = #widget{tags = T, state = S}) ->
    Char = case {lists:member(capslock,T), lists:member(shift_held,T)} of
        {true, true} when (Shift >= $A) and (Shift =< $Z) -> Unshift;
        {true, false} when (Shift >= $A) and (Shift =< $Z) -> Shift;
        {_, true} -> Shift;
        _ -> Unshift
    end,

    #state{xs = Xs0, text = Text0, cursor = Cursor0, mask = M} = S,
    TextBefore = binary:part(Text0, {0, Cursor0}),
    XsBefore = lists:sublist(Xs0, Cursor0 + 1),

    TextAfter0 = binary:part(Text0, {Cursor0, byte_size(Text0) - Cursor0}),
    TextAfter1 = <<Char, TextAfter0/binary>>,

    Xs1 = XsBefore ++ calc_xs(TextBefore, TextAfter1, Wd#widget.size, M),
    Text1 = <<TextBefore/binary, TextAfter1/binary>>,
    Cursor1 = Cursor0 + 1,

    S2 = S#state{xs = Xs1, text = Text1, cursor = Cursor1},
    handle(redraw_text, Wd#widget{state = S2});

handle(#ts_inpevt_key{action = up}, Wd = #widget{state = S}) ->
    {ok, Wd, []};

handle(focus, Wd = #widget{tags = T, state = S}) ->
    #state{text = Text} = S,
    TextLen = byte_size(Text),
    S2 = S#state{cursor = TextLen},
    case lists:member(focus, T) of
        true -> {ok, Wd, []};
        false ->
            handle(redraw_base, Wd#widget{state = S2, tags = [focus | T]})
    end;

handle(#ts_inpevt_mouse{action = down, buttons = [1], point = {X,Y}}, Wd = #widget{tags = T, size = {W,H}, state = S}) ->
    YFrac = Y / H,
    #state{xs = Xs} = S,
    S2 = if
        (YFrac > 0.1) andalso (YFrac < 0.9) ->
            NewCursor = length(lists:takewhile(fun(XX) -> XX < X end, Xs)) - 1,
            S#state{cursor = NewCursor};
        true -> S
    end,
    case lists:member(focus, T) of
        true ->
            handle(redraw_text, Wd#widget{state = S2});
        false ->
            handle(redraw_base, Wd#widget{state = S2, tags = [focus | T]})
    end;

handle(#ts_inpevt_mouse{action = move}, Wd = #widget{tags = T}) ->
    case lists:member(mouse_in, T) of
        true -> {ok, Wd, []};
        false -> handle(redraw_base, Wd#widget{tags = [mouse_in | T]})
    end;

handle(mouse_out, Wd = #widget{tags = T}) ->
    case lists:member(mouse_in, T) of
        false -> {ok, Wd, []};
        _ -> handle(redraw_base, Wd#widget{tags = T -- [mouse_in]})
    end;

handle(blur, Wd = #widget{tags = T}) ->
    case lists:member(focus, T) of
        false -> {ok, Wd, []};
        _ -> handle(redraw_base, Wd#widget{tags = T -- [focus]})
    end;

handle({resize, {W,H}}, Wd = #widget{state = S, tags = T}) ->
    handle(redraw_base, Wd#widget{size = {W,H}});

handle(redraw_base, Wd = #widget{state = S, tags = T, size = Sz, format = F}) ->
    Img = base(T, Sz, F),
    S2 = S#state{base = Img},
    handle(redraw_text, Wd#widget{state = S2});

handle(redraw_text, Wd = #widget{state = S, tags = T, size = {W, H}}) ->
    #state{text = Text, cursor = N, xs = Xs, base = Image0, placeholder = Placeholder, mask = Mask} = S,
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

handle(Event, Wd) ->
    ui:default_handler(Event, Wd).
