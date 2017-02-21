# **wampcc**

**wampcc** is C++ library that implements the [Web Application Messaging Protocol (WAMP)](http://wamp.ws/) protocol.

**wampcc** provides the WAMP basic profile for client roles and also a lightweight implementation of a WAMP router / dealer.

**Features**

 - Roles: Caller, Callee, Subscriber, Publisher, Dealer, Router
 - Serializations: JSON
 - Transports: TCP using raw-socket and web-socket
 - Uses modern C++
 - Extensively tested
 - Permissive license (MIT)

**Dependencies**

 - [libuv](http://libuv.org/) for socket IO
 - [jansson](http://www.digip.org/jansson/) for JSON encoding
 - [http-parser](https://github.com/nodejs/http-parser)
 - C++11 compiler, GNU autotools

## Show me some code!

Here is what programming with **wampcc** looks like:

**Establishing a wamp session**

```c++
/* Create the wampcc kernel */
kernel my_kernel({}, logger::stdout());

/* Create the TCP socket and attempt to connect */
std::unique_ptr<tcp_socket> my_socket(new tcp_socket(&my_kernel));
my_socket->connect("127.0.0.1", 55555).wait();

/* If connected, create a wamp session */
if (my_socket->is_connected())
{
  auto my_session = wamp_session::create<rawsocket_protocol>(
      &my_kernel,
      std::move(my_socket),
      [](session_handle, bool) { /* handle on-close */ }, {});
}
```

**Calling a remote procedure**

```c++
my_session->call(
  "math.service.add", {}, {{100,200},{}},
  [](wamp_call_result result) {
    if (result)
      std::cout << "got result: " << result.args.args_list[0] << std::endl;
  });
```

**Registering a remote procedure**
```c++
my_session->provide("math.service.add", {},
  [](wamp_invocation& invoke) {
    int total = 0;
    for (auto & item : invoke.args.args_list)
      if (item.is_int())
        total += item.as_int();
    invoke.yield({total}, {});
  });
```
