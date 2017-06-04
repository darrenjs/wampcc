unreleased
==========

## Added

* msgpack serialiser support
* using websocketpp project for websocket protocol

version 1.3.1
=============

Released 2017-06-02

## Fixed

- configure script can handle relative path to source, when invoked

- using case-insensitive string comparison when processing HTTP headers

- examples now are built statically

version 1.3
===========

Released 2017-05-31

## Added

- support build on Windows, thanks to @petten for cmakefiles & ideas

## Fixed

- memory leak on each new wamp_session

## Other

- soname: 3.0.0

version 1.1.1
=============

Released 2017-04-16

## Added

- admin tool can use either websocket or rawsocket

## Fixed

- bug fix: incorrect array index during invocation processig
- bug fix: websocket client was not apply frame mask (issue by user 'petten')

version 1.1.0
=============

Released 2017-04-14

## Added

- TLS/SSL support using OpenSSL, in both client and server mode

version 1.0.0
=============

Released 2017-03-03

- initial release
