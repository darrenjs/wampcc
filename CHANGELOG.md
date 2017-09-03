unreleased
==========

## Added

- websocket listener replies with http 200 on receiving health check

- basic example of using SSL to connect to WSS

## Changed

- project directory structure fully reorganised (suggested by Daniel Kesler)

- new cmake approach (added by Daniel Kesler)

- sister project, jalson, now integrated into wampcc

- large scale api refactor of wamp_session, to adopt a uniform approach
  for interaction with user code, and to make the link clearer between api
  calls and the underlying WAMP interaction

- websocket protocol automatically adds http Host: header -- often
  required by other wamp providers or gateways

- timeout duration for logon increased from 10 to 30, also now configurable

- websocket pongs contain ping payload, and use different config for
  minimum interval between successive messages

## Fixed

- cmake build supported on linux

- msgpack encode/decode failed for values outside int range (issue #6, Green7)

- session mode incorrectly accessed during inbound error handling

- token searching failure for Sec-WebSocket-Protocol field

- nonce generator was returning empty string

version 1.4
===========

Released 2017-07-07

## Added

- using websocketpp project for websocket protocol

- using catch-like test framework (aim is to be compatible with catch, so that
  catch can be used via minor change to header file inclusion).

- public version info placed in version.h

- automatic build (via autotools) of some example programs (issue #3)

- example/wamp_router, which will aim to provide an example of a router

- example/wampcc_tester, for integration testing

## Removed

- fetch and link of googletest, was not being used

## Changed

- wamp_session::provide() accept callback that is invoked on success/failure of
  registration.

- Using msgpack-c 2.1.3.  In this version the header-only msgpack decoder has
  been fixed, which is used by wampcc.

- The stream logger (used by the logger::console logger) now takes a wrapper to
  a ostream& and a mutex, instead of just an ostream reference.  This is so that
  a synchronization mechanism is available to synchronize writes to the
  stream (issue #2, petten).

## Fixed

- wamp_session not handling failed registration

- compile errors on Xcode 7.3.1 + 10.7 SDK (issue #2, petten)

- cmake missing link libraries on Linux

- websocket opening assumed Sec-WebSocket-Protocol would be present, but
  acutally its optional header

- memory leaks in jalson, and msgpack protocol

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
