%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-ifndef(KBD_MACROS).

-define(KBDL_US, 16#409).
-define(KBDL_US_DVORAK, 16#10409).

-define(KBD_IBM83, 16#01).
-define(KBD_ICO102, 16#02).
-define(KBD_IBM84, 16#03).
-define(KBD_IBM101, 16#04).
-define(KBD_JAPAN, 16#07).

-define(KBD_SCANCODES, {
	null, esc, {$1, $!}, {$2, $@}, 			%  0
	{$3, $#}, {$4, $$}, {$5, $%}, {$6, $^}, %  4
	{$7, $&}, {$8, $*}, {$9, $(}, {$0, $)}, %  8
	{$-, $_}, {$=, $+}, bksp, tab, 			% 12
	{$q, $Q}, {$w, $W}, {$e, $E}, {$r, $R}, % 16
	{$t, $T}, {$y, $Y}, {$u, $U}, {$i, $I}, % 20
	{$o, $O}, {$p, $P}, {$[, ${}, {$], $}}, % 24
	enter, ctrl, {$a, $A}, {$s, $S},		% 28
	{$d, $D}, {$f, $F}, {$g, $G}, {$h, $H},	% 32
	{$j, $J}, {$k, $K}, {$l, $L}, {$;, $:}, % 36
	{$', $"}, {$`, $~}, shift, {$\\, $|},	% 40
	{$z, $Z}, {$x, $X}, {$c, $C}, {$v, $V},	% 44
	{$b, $B}, {$n, $N}, {$m, $M}, {$,, $<}, % 48
	{$., $>}, {$/, $?}, shift, prisc,		% 52
	alt, space, caps, f1,					% 56
	f2, f3, f4, f5,							% 60
	f6, f7, f8, f9,							% 64
	f10, num, scroll, home,					% 68
	up, pgup, 'gray-', left,				% 72
	center, right, 'gray+', 'end',			% 76
	down, pgdown, ins, del,					% 80
	null, null, null, f11,					% 84
	f12, null, null, null					% 88
	}).

-define(KBD_MACROS, 1).
-endif.
