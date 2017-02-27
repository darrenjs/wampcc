# **wampcc**

**wampcc** is C++ library that implements the [Web Application Messaging Protocol (WAMP)](http://wamp-proto.org/) protocol.

*wampcc* provides the WAMP basic profile for client roles and also a lightweight implementation of a WAMP router / dealer.

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

Here is what programming with *wampcc* looks like.

**Establishing a WAMP session**

Before a WAMP session can be established, a `tcp_socket` has to be created and connected to a WAMP router / dealer server.

Once the connected socket is available, a `wamp_session` object is constructed and an attempt is made to logon to a realm.

All *wampcc* objects make use of a shared `kernel` object, which provides the internal threads and socket IO.

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

C++ lambdas are used to process the asynchronous result of a call request, and this usage pattern is the same for other kinds of request.

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


## Building wampcc

Building *wampcc* involves serveral steps, including: installation of build tools; building dependent libraries; obtaining the source; and source configuration.

**Setting up build tools**

Building on linux presumes that some essential programs are available, including:

- git
- autoconf
- g++
- make
- wget
- libtool
- libssh headers & libraries

*wampcc* was developed on *xubuntu* 14.04, and these tools can be installed using the command:

```bash
apt-get install git autoconf gcc g++ make wget libtool libssl-dev
```

**Building dependent libraries**

*wampcc* requires the C libraries *libuv* and *jansson* have already been built and installed.  The location of these libraries must be provided during the *wampcc* source configuration step.

**Obtaining the source**

The latest version of *wampcc* can be downloaded from github using:

```bash
git clone https://github.com/darrenjs/wampcc.git
```

This will fetch the source files directly from github and place them in a directory named `wampcc/`.

Additional source files are contained in a separate project **jalson**, which provides the *wampcc* json types.  To obtain these sources run the `fetch_prerequisites.sh` script:

```bash
cd wampcc/
./fetch_prerequisites.sh
```

Assuming no download problems the additional files can be found in the `jalson/` subdirectory.

**Source configuration**

If building from the git sources, then the `configure` script must be first generated.  An included helped script can be run to do this:

```bash
./autotools_setup.sh
```

The source code is now ready to be configured.  This is done by running the `configure` script, and passing it the locations of *libuv* and *jansson*, and also the location where *wampcc* should finally be installed.

```bash
./configure  --prefix=/var/tmp/wampcc_install  --with-libuv=/opt/libuv-1.10.2 --with-jansson=/opt/jansson-2.7
```

Note that the locations of *libuv* and *jansson* will be specific to your host, and will not likely exactly match this example.

Finally the build and install steps are run:

```bash
make install
```

If all goes well *wampcc* will be installed into the `prefix` location.
