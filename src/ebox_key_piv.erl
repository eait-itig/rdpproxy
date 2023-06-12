%%
%% ebox
%% pivy box/ebox parsing for Erlang
%%
%% Copyright 2022 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(ebox_key_piv).

-compile([{parse_transform, lager_transform}]).

-behaviour(ebox_key).

-export([
    get_public/1,
    compute_key/2
    ]).

-include_lib("public_key/include/public_key.hrl").

-type slot() :: nist_piv:slot().
-type keydata() :: {pid(), slot(), ebox:pubkey()}.

-spec get_public(Data :: keydata()) -> {ok, PubKey :: ebox:pubkey()}.
get_public({_Piv, _Slot, PubKey}) ->
    {ok, PubKey}.

-spec compute_key(Partner :: ebox:pubkey(), Data :: keydata()) ->
    {ok, SharedSecret :: binary()}.
compute_key(Partner, {Piv, Slot, PubKey}) ->
    Algo = nist_piv:algo_for_key(PubKey),
    {PubPoint, _} = ebox_crypto:decompress(Partner),
    {ok, [{ok, DH}]} = apdu_transform:command(Piv, {ecdh, Slot, Algo, PubPoint}),
    {ok, DH}.
