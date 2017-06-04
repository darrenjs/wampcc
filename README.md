# **wampcc**

**wampcc** is C++ library that implements the [Web Application Messaging Protocol (WAMP)](http://wamp-proto.org/) protocol.

*wampcc* provides the WAMP basic profile for client roles and also a lightweight implementation of a WAMP router / dealer.

**Features**

 - Builds on: Linux & Windows (Visual Studio)
 - Roles: Caller, Callee, Subscriber, Publisher, Dealer, Router
 - Message serializations: JSON
 - Transports: TCP using raw-socket and web-socket
 - SSL/TLS supported for both client and server sessions
 - Uses modern C++
 - Extensively tested
 - Permissive license (MIT)

**Dependencies**

*wampcc* aims to depend mostly on C libraries, making it easier to build and work on a range of platforms.

 - [libuv](http://libuv.org/) (network IO)
 - [jansson](http://www.digip.org/jansson/) (JSON encode & decode)
 - [http-parser](https://github.com/nodejs/http-parser)
 - [OpenSSL](https://www.openssl.org/)
 - [websocketpp](https://www.zaphoyd.com/websocketpp) -- C++ header only
 - Modern C++ compiler, GNU autotools (Linux build), CMake (Windows build)

## Show me some code!

Here is what programming with *wampcc* looks like.

**Establishing a WAMP session**


Before a WAMP session can be established, a `tcp_socket` has to be created and connected to a WAMP router / dealer server.

After the socket is successfully connected it is used to construct a `wamp_session`. Next the login sequence is initiated to establish the logical WAMP session.

All *wampcc* objects make use of a shared `kernel` object, which provides threads for event handling and socket IO.

```c++
/* Create the wampcc kernel. */

kernel the_kernel;

/* Create the TCP socket and attempt to connect. */

std::unique_ptr<tcp_socket> socket(new tcp_socket(&the_kernel));
socket->connect("127.0.0.1", 55555).wait_for(std::chrono::seconds(3));

if (!socket->is_connected())
  throw std::runtime_error("connect failed");

/* With the connected socket, create a wamp session & logon to the realm
 * called 'default_realm'. */

auto session = wamp_session::create<rawsocket_protocol>(
  &the_kernel, std::move(socket));

session->initiate_hello({"default_realm"}).wait_for(std::chrono::seconds(3));

if (!session->is_open())
  throw std::runtime_error("realm logon failed");
```

**Calling a remote procedure**

C++ lambda functions are used to handle the asynchronous result of a call request, and this usage pattern is the same for other kinds of request.

This example shows a request to call a remote procedure named **math.service.add** with arguments **100** & **200**.

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
      if (item.is_int())
        total += item.as_int();
    invoke.yield({total});
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

A thread can wait for a `wamp_session` to be remotely closed by waiting on an appropriate `std::future`. A `wamp_session` that is no longer needed must be closed and the closure operation completed before it can be deleted.

```c++
session->closed_future().wait_for(std::chrono::minutes(10));
session->close().wait();
```

**Embedding a wamp router**

An embedded wamp router is provided by creating a `wamp_router` object.

```c++
wamp_router router(&the_kernel);
```

It is instructed to begin listening on a particular port for new clients, together with the policy to use for authentication.

```c++
/* Accept clients on IPv4 port, without authentication. */

auto fut = router.listen(auth_provider::no_auth_required(), 55555);

if (auto ec = fut.get())
  throw runtime_error(ec.message());
```

An individual RPC is provided by defining the realm & name through which it can be called by a WAMP session, together with the lambda function which does the actual work of yielding a response.

```c++
router.provide(
    "default_realm", "greeting", {},
    [](wamp_invocation& invocation) { invocation.yield({"hello"}); });
```

The complete listing for these examples can be found at:

 - [demo_embedded_router.cc](https://github.com/darrenjs/wampcc/blob/master/examples/basic/demo_embedded_router.cc)
 - [demo_client.cc](https://github.com/darrenjs/wampcc/blob/master/examples/basic/demo_client.cc)


## Building wampcc

Building *wampcc* involves several steps, including: installation of build tools; building the dependent libraries; obtaining the source; and source configuration.

**Setting up build tools**

Building on Linux presumes that some essential programs are available, including:

- git
- autoconf
- g++
- make
- wget
- libtool
- libssh headers & libraries

*wampcc* was developed on *xubuntu* and on this system these tools can be installed using the command:

```bash
apt-get install git autoconf gcc g++ make wget libtool libssl-dev
```

**Building dependent libraries**

*wampcc* requires that the C libraries *libuv* and *jansson* have already been built and installed.  The location of these libraries must be provided during the *wampcc* source configuration step.

**Obtaining the source**

The latest version of *wampcc* can be downloaded from github using:

```bash
git clone https://github.com/darrenjs/wampcc.git
```

This will fetch the source files directly from github and place them in a directory named `wampcc/`.

Additional source files are contained in a separate project named **jalson**, which provides the *wampcc* json types.  To obtain these sources run the `fetch_prerequisites.sh` script:

```bash
cd wampcc/
./fetch_prerequisites.sh
```

Assuming no download problems the additional files can be found in the `jalson/` sub-directory.

**Source configuration**

If building from the git sources the `configure` script must be first generated.  An included helped script can do this:

```bash
./autotools_setup.sh
```

The source code is now ready to be configured.  This is done by running the `configure` script, and passing it the locations of *libuv* and *jansson*, and also the location where *wampcc* should finally be installed.

```bash
./configure  --prefix=/var/tmp/wampcc_install  --with-libuv=/opt/libuv-1.10.2 --with-jansson=/opt/jansson-2.10
```

Note that the locations of *libuv* and *jansson* will be specific to your host, and will unlikely match this example.

Finally the build and install steps are run:

```bash
make install
```

If all goes well *wampcc* will be installed into the `prefix` location.
