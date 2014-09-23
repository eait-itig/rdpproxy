%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(tpkt).

-export([encode/1, decode/1]).

-spec encode(Binary :: binary()) -> {ok, binary()}.
encode(Binary) ->
    Sz = byte_size(Binary) + 4,
    {ok, <<3, 0, Sz:16/big, Binary/binary>>}.

-spec decode(Binary :: binary()) -> {ok, Body :: binary()} | {error, term()}.
decode(Binary) ->
    case Binary of
        <<3, 0, Length:16/big, Rest/binary>> ->
            RealLength = Length - 4,
            RemLength = byte_size(Rest),
            if RealLength =< RemLength ->
                <<Body:RealLength/binary, Rem/binary>> = Rest,
                {ok, Body, Rem};
            true ->
                {error, bad_length}
            end;
        _ ->
            {error, bad_tpkt}
    end.
