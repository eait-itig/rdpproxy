A login proxy and load-balancer for Microsoft Remote Desktop (RDP), as used for `rdp.labs.eait.uq.edu.au`.

## What is it for?

The rdpproxy sits between a large pool of client machines (running, eg, Windows 7 Enterprise) and the Internet. The idea is to make remote desktop on these client machines available to Internet users securely, without exposing the machines themselves (so they can remain on private IPs etc).

The RDP proxy accepts connections from external users (and enforces the use of TLS/SSL on them), then itself draws a login screen. Once the user's credentials have been validated by the proxy (via LDAP), it then opens a connection to a chosen back-end server (from the pool) and forwards all traffic.

If the external user disconnects and re-connects later and their session is still open on the back-end server, they will always be forwarded back to the same one. Additionally, the RDP proxy integrates with an agent that can run on each client machine to keep its records of when sessions begin and end up to date. It also performs probes on the back-end servers to check which are available for use.

## Structure of the code

3 OTP applications:

 * `rdp_proto` -- core RDP protocol encoding/decoding (ASN.1 etc), plus bitmap compression algorithms (based on FreeRDP code)
 * `rdp_ui` -- a very minimal widget toolkit used to draw the login screen and messages
 * `rdpproxy` -- rest of the code

Within the `rdpproxy` application (in this repository), there are a couple of major components:

 * `frontend` and `frontend_sup` -- the main acceptor pool and protocol FSM that talks to Internet clients
 * `backend` (supervised by a `frontend`) -- simplified protocol FSM for probing and forwarding to/from a connection to a back-end machine
 * `ui_fsm` and `ui_fsm_sup` -- the login screen UI FSM, including code that uses `rdp_ui` to draw things on the screen and handle events
 * `db_cookie` and `db_host_meta` -- store session info and load-balancer metadata in Riak
 * `http_api`, `http_*_handler` -- implement the HTTP callback API that back-end agents use to update the proxy's status information about sessions (who is logged on where etc)

## etc
TODO: more documentation and testing
