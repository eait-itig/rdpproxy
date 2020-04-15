A login proxy and load-balancer for Microsoft Remote Desktop (RDP), as used for
`rdp.labs.eait.uq.edu.au`.

## What is it for?

The rdpproxy sits between a large pool of client machines (running, eg, Windows
7 Enterprise) and the Internet. The idea is to make remote desktop on these
client machines available to Internet users securely, without exposing the
machines themselves (so they can remain on private IPs etc).

The RDP proxy accepts connections from external users (and enforces the use of
TLS/SSL on them), then itself draws a login screen. Once the user's credentials
have been validated by the proxy (via KRB5), including the use of Duo 2FA, it
then opens a connection to a chosen back-end server (from the pool) and forwards
all traffic.

If the external user disconnects and re-connects later and their session is
still open on the back-end server, they will always be forwarded back to the
same one. Additionally, the RDP proxy integrates with an agent that can run on
each client machine to keep its records of when sessions begin and end up to
date. It also performs probes on the back-end servers to check which are
available for use.

The rdpproxy can also be set up with multiple "pools" of backend servers and
present a choice of which to use to connecting users.

## Advantages

 * Keeps your backend machines on private IPs away from the Internet
 * Stops multiple users fighting over the same backend machine
 * Helps protect against RDP brute force
 * Enforces 2FA
 * Doesn't interfere with use of RDP features like device redirection,
   video remoting, etc, since after login the proxy just forwards your traffic
   directly to the backend without altering it.

## Setting up

This code is designed to build with `rebar3`, on OTP 21.3 or later. You'll
need OTP and `rebar3` installed and in your `PATH` to compile it.

Before building the proxy, edit the config to reflect your local setup:

```
$ cp config/sys.config{.dist,}
$ cp config/vm.args{.dist,}
$ vi config/sys.config
$ vi config/vm.args
```

You will definitely need to change hostnames, KRB5/AD realm names, randomize
the encryption key used for temporary password storage, randomize the set-cookie
argument in `vm.args` and probably also set service keys for KRB5 (if
authenticating against AD).

If running the rdpproxy in an HA cluster, set the Erlang node names in the `ra`
configuration section. Dynamic cluster reconfiguration is not currently
supported, so if you need to change this later you will need to re-initialise
the database. Note that Raft is used for managing consensus in the cluster,
which means that a majority of nodes have to be running for it to make any
progress (so e.g. running 2 nodes is pointless, and odd numbers are a better
idea).

If you want to add your own logo graphic for the login screen, you should also
add it to the `apps/rdpproxy/priv` directory before building and edit the
configuration to point at it.

When you're done configuring, generate the release:

```
$ rebar3 release
```

This will create a dir in the `_build/default/rel` named `rdpproxy` which
contains a complete OTP release ready to run. You should copy this to a path
on your machine where you want to run the rdpproxy (e.g. `/opt/rdpproxy`).

To start it, run `/path/to/release/bin/rdpproxy start`.

## Managing machines

Currently there are two approaches for managing the set of backend hosts which
the rdpproxy will use:

1. Use the status report agent, which accepts HTTP PUTs on port 8088 (by
default) and updates a host's information based on the report.
2. Use the `rdpproxy-admin` commandline tool to create hosts by hand.

For option 1, you will need to set the `report_roles` property on a pool so
that rdpproxy knows where to store the dynamically created hosts known via HTTP.
For example, setting this on the `default` pool (which is automatically created
at startup):

```
$ rdpproxy-admin pool update default '#{report_roles => [<<"foobar">>]}'
```

For option 2, you can use commands like the following to set the host
information:

```
$ rdpproxy-admin host create <pool> <ip>
$ rdpproxy-admin host enable <ip>
```

You can confirm the status of pools and machines using other commands available
through `rdpproxy-admin` as well:

```
$ rdpproxy-admin pool list
              ID                           TITLE          MODE   CHOICE                      ROLES   MIN RSVD TIME    HDL EXP TIME    HOSTS#     HDLS#
        coms4103           Prac Lab for COMS4103   single_user     true                          -            3600             900         3         0
         default                    Virtual Labs   single_user    false               vlab,desktop            1800             900       289        32
        dlthesis          DL Thesis Lab (78-108)   single_user     true                          -            3600             900         3         1
           gs336             DL GPU Lab (78-336)   single_user    false                          -            3600             900        41         1

$ rdpproxy-admin host list dlthesis
      POOL                IP                HOST   ENABLED                     LASTERR                    LASTUSER          SESSIONS             IMAGE      ROLE                REPSTATE         REPORT
  dlthesis     10.240.xxx.xx  gs108-xxxx.labs.ea      true                           -     s4xxxxxx (3d 15hr  ago)       0 act/0 rdy              none      none  available (6d 4hr  ago              -
  dlthesis    10.240.xxx.xxx  gs108-xxxx.labs.ea      true                           -      s4xxxxxx (6hr 1m  ago)       1 act/0 rdy              none      none  available (6d 4hr  ago              -
  dlthesis    10.240.xxx.xxx  gs108-xxxx.labs.ea      true                           -      s4xxxxxx (5hr 2m  ago)       0 act/0 rdy              none      none  available (6d 4hr  ago              -

$ rdpproxy-admin host get 10.240.xxx.xxx
IP            10.240.xxx.xxx
HOSTNAME      gs108-xxxx.labs.eait.uq.edu.au
ENABLED       true
IMAGE         none
ROLE          none
LAST REPORT   -
REPORT STATE  available (6d 4hr  ago)

           HANDLE              USER       STATE                 START                   MIN                EXPIRY                   PID
 C8UO6pcZBIT1RaF5          s4xxxxxx          ok           6hr 1m  ago           5hr 1m  ago                     -      <29275.14834.18>

RECENT USERS
 * s43xxxxx (5d 7hr  ago)
 * s44xxxxx (1d 23hr  ago)
 * s44xxxxx (1d 20hr  ago)
 * s44xxxxx (6hr 1m  ago)

RECENT ERRORS

REPORTED SESSIONS
```

And see what the sorted list of available machines for a new user would be if
they logged in at the present time:

```
$ rdpproxy-admin alloc host default nobody
              IP                HOST   ENABLED                     LASTERR                    LASTUSER                     LASTREP          SESSIONS             IMAGE      ROLE                REPSTATE         REPORT
  10.240.xxx.xxx  gs208-xxxx-v.labs.      true                           -      s4xxxxxx (1d 2hr  ago)      s4xxxxxx (1d 2hr  ago)       0 act/0 rdy  labs-20200305-18      vlab  available (21hr 2m  ag     2m 21s ago
   10.240.xxx.xx  gs122-xxxx-v.labs.      true                           -      s4xxxxxx (1d 2hr  ago)      s4xxxxxx (1d 2hr  ago)       0 act/0 rdy  labs-20200305-18      vlab  available (1d 1hr  ago      3m 0s ago
  10.240.xxx.xxx  gs208-xxxx-v.labs.      true                           -      s4xxxxxx (1d 1hr  ago)      s4xxxxxx (1d 1hr  ago)       0 act/0 rdy  labs-20200305-18      vlab     available (1d  ago)        48s ago
   10.240.xxx.xx  gs122-xxxx-v.labs.      true                           -      s4xxxxxx (1d 1hr  ago)      s4xxxxxx (1d 1hr  ago)       0 act/0 rdy  labs-20200305-18      vlab  available (13hr 37m  a     3m 22s ago
  10.240.xxx.xxx  gs122-xxxx-v.labs.      true                           -      s4xxxxxx (1d 1hr  ago)      s4xxxxxx (1d 2hr  ago)       0 act/0 rdy  labs-20200305-18      vlab  available (1d 1hr  ago     1m 18s ago
  10.240.xxx.xxx  hn301-xxxx-v.labs.      true                           -          s4xxxxxx (1d  ago)          s4xxxxxx (1d  ago)       0 act/0 rdy  labs-20200305-18      vlab     available (1d  ago)        31s ago
  10.240.xxx.xxx  hn301-xxxx-v.labs.      true                           -          s4xxxxxx (1d  ago)          s4xxxxxx (1d  ago)       0 act/0 rdy  labs-20200305-18      vlab     available (1d  ago)     9m 52s ago
   10.240.xxx.xx  hn301-xxxx-v.labs.      true                           -          s4xxxxxx (1d  ago)          s4xxxxxx (1d  ago)       0 act/0 rdy  labs-20200305-18      vlab  available (23hr 16m  a     1m 20s ago
   10.240.xxx.xx  hn301-xxxx-v.labs.      true                           -          s4xxxxxx (1d  ago)          s4xxxxxx (1d  ago)       0 act/0 rdy  labs-20200305-18      vlab  available (23hr 47m  a     4m 58s ago
   	...
```

## Viewing current state

You can also view all of the users currently connected by running the command
`rdpproxy-admin conn list`:

```
$ rdpproxy-admin conn list
              ID                      PEER        NODE         STARTED        USER            HANDLE          BACKEND        POOL   PROTVER         REMHOST          RES     RECONN
IezPe0rhxxxxxxxx      203.220.xxx.x :49449  rdpproxy2.     6hr 6m  ago    s4xxxxxx  C8UO6pcGxxxxxxxx   10.240.xxx.xxx    dlthesis      8.12  DESKTOP-XXXXXX    1920x1080         no
xxxxxxxxBKzIecrF    193.116.xxx.xxx :51031  rdpproxy1.     5hr 9m  ago    s4xxxxxx  Hr5Ew02exxxxxxxx     10.240.xxx.x     default       8.4      XXXXXXX-PC     1600x900         no
icLIjjwxxxxxxxxx        172.18.xx.x :50983  rdpproxy2.    3hr 55m  ago    s4xxxxxx  h7fwEb7xxxxxxxxx    10.240.xxx.xx     default      8.11  DESKTOP-XXXXXX    1920x1080        yes
...
count: 30
```

This shows information including the peer remote IP and port for the connection,
which node of the rdpproxy cluster they are connected to, which backend they're
using, whether the connection is the result of auto-reconnect, and other details
about the client's version and local hostname.

## Structure of the code

3 OTP applications:

 * `rdp_proto` -- core RDP protocol encoding/decoding (ASN.1 etc), plus bitmap compression algorithms (based on FreeRDP code) and the protocol state machines
 * `rdp_ui` -- a very minimal widget toolkit used to draw the login screen and messages
 * `rdpproxy` -- rest of the code

Within the `rdpproxy` application (in this repository), there are a couple of major components:

 * `frontend` -- an implementation of the `rdp_server` behaviour from `rdp_proto` which handles connections
 * `backend` (supervised by a `frontend`) -- simplified protocol FSM for probing and forwarding to/from a connection to a back-end machine
 * `ui_fsm` and `ui_fsm_sup` -- the login screen UI FSM, including code that uses `rdp_ui` to draw things on the screen and handle events
 * `db_cookie` and `db_host_meta` -- store session info and load-balancer metadata in Riak
 * `http_api`, `http_*_handler` -- implement the HTTP callback API that back-end agents use to update the proxy's status information about sessions (who is logged on where etc)

## etc
TODO: more documentation and testing
