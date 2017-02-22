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

**Establishing a WAMP session**

Before a WAMP session can be established, a `tcp_socket` has to be created and
connected to a WAMP router / dealer server.

Once the connected socket is available, the `wamp_session` object is constructed
and an attempt is made to logon to a realm.

All **wampcc** objects make use of a shared `kernel` object, which provides the
internal threads and socket IO.

```c++
/* Create the wampcc kernel. */

kernel the_kernel({}, logger::stdout());

/* Create the TCP socket and attempt to connect. */

std::unique_ptr<tcp_socket> socket(new tcp_socket(&the_kernel));
socket->connect("127.0.0.1", 55555).wait_for(std::chrono::seconds(3));

if (not socket->is_connected())
  throw std::runtime_error("connect failed");

/* With the connected socket, create a wamp session & logon to the realm
 * called 'default_realm'. */

auto session = wamp_session::create<rawsocket_protocol>(
  &the_kernel,
  std::move(socket),
  [](session_handle, bool) { /* handle on-close */ }, {});

session->initiate_hello({"default_realm"}).wait_for(std::chrono::seconds(3));

if (not session->is_open())
  throw std::runtime_error("realm logon failed");
```

**Calling a remote procedure**

C++ lambdas are used to process the asynchronous result of a call request, and
this usage pattern is the same for other kinds of request.

```c++
session->call(
  "math.service.add", {}, {{100,200},{}},
  [](wamp_call_result result) {
    if (result)
      std::cout << "got result: " << result.args.args_list[0] << std::endl;
  });
```

**Registering a remote procedure**
```c++
session->provide(
  "math.service.add", {},
  [](wamp_invocation& invoke){
    int total = 0;
    for (auto & item : invoke.args.args_list)
      if (item.as_int())
        total += item.as_int();
    invoke.yield({total}, {});
  });
```

**Subscribing to a topic**
```c++
session->subscribe(
  "random_number", {},
  [](wamp_subscribed& subscribed) {
    std::cout << "subscribed " << (subscribed?"ok":"failed") << std::endl;
  },
  [](wamp_subscription_event ev) {
    for (auto & x : ev.args.args_list)
      std::cout << x << " ";
    std::cout << std::endl;
  });
```

**Publishing to a topic**
```c++
std::srand(std::time(0)); //use current time as seed for random generator
int random_variable = std::rand();
session->publish("random_number", {}, {{random_variable},{}});
```

**Terminating a session**

A thread can wait for a session to be closed by waiting on a `std::future` that is accessible from the `wamp_session`.

```c++
session->closed_future().wait_for(std::chrono::minutes(10));
session->close().wait();
```
