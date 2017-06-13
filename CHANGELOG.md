unreleased
==========

## Added

- msgpack serialiser support

- using websocketpp project for websocket protocol

- public version info placed in version.h

- automatic build (via autotools) of some example programs (issue #3)

## Removed

- fetch and link of googletest, was not being used

## Changed

- wamp_session::provide() accept callback that is invoked on success/failure of
  registration.

- Using msgpack-c 2.1.2.  In this version the header-only msgpack decoder has
  been fixed, which is used by wampcc.

- The stream logger (used by the logger::console logger) now takes a wrapper to
  a ostream& and a mutex, instead of just an ostream reference.  This is so that
  a synchronization mechanism is available to synchronize writes to the
  stream (issue #2, petten).

## Fixed

- wamp_session not handling failed registration

- compile errors on Xcode 7.3.1 + 10.7 SDK (issue #2, petten)

- cmake missing link libraries on Linux

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
