#!/bin/sh

PATH=.:$PATH
test_tcp_socket_connect                     23000
test_tcp_socket_connect_cb                  23100
test_wamp_rpc                               23200
test_tcp_socket_listen                      23300
test_tcp_socket_passive_disconnect          23400
test_early_wamp_session_destructor          23500
test_late_wamp_session_destructor           23600
test_late_dealer_destructor                 23700
test_evthread_wamp_session_destructor       23800
#test_dealer_disconnect_when_has_connections 23900
test_wamp_session_fast_close                24000
test_tcp_socket                             24100
test_connect_timeout                        24200

echo Note: test test_dealer_disconnect_when_has_connections has been commented out.





