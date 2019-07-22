# **wampcc**

**wampcc** is C++ library that implements the [Web Application Messaging Protocol (WAMP)](http://wamp-proto.org/) protocol.

*wampcc* provides the WAMP basic profile for client roles and also a lightweight implementation of a WAMP router / dealer.

**Features**

 - Builds on: Linux, Windows (Visual Studio) & Mac OS 10
 - Roles: Caller, Callee, Subscriber, Publisher, Dealer, Router
 - Message serializations: JSON, MessagePack
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
 - [msgpack-c](https://github.com/msgpack/msgpack-c) -- C++ header only
 - Modern C++ compiler, GNU autotools (Linux), CMake (Linux & Windows)

## Show me some code!

Here is what programming with *wampcc* looks like.

**Establishing a WAMP session**


Before a WAMP session can be established, a `tcp_socket` has to be created and connected to a WAMP router / dealer server.

After the socket is successfully connected it is used to construct a `wamp_session`. Next the HELLO sequence is initiated to establish the logical WAMP session.

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

auto session = wamp_session::create<websocket_protocol>(
  &the_kernel, std::move(socket));

session->hello("default_realm").wait_for(std::chrono::seconds(3));

if (!session->is_open())
  throw std::runtime_error("realm logon failed");
```

**Calling a remote procedure**

C++ lambda functions are used to handle the asynchronous result of a call request, and this usage pattern is the same for other kinds of request.

This example shows a request to call a remote procedure named **math.service.add** with arguments **100** & **200**.

```c++
session->call("math.service.add", {}, {{100, 200}, {}},
              [](wampcc::wamp_session&, wampcc::result_info result) {
                if (result)
                  std::cout << "got result: " << result.args.args_list[0] << std::endl;
              });
```

**Registering a remote procedure**

```c++
session->provide("math.service.add", {},
                 [](wamp_session&, registered_info info) {
                   if (info)
                     std::cout << "procedure registered with id "
                               << info.registration_id << std::endl;
                   else
                     std::cout << "procedure registration failed, error "
                               << info.error_uri << std::endl;
                 },
                 [](wamp_session& ws, invocation_info info) {
                   int total = 0;
                   for (auto& item : info.args.args_list)
                     if (item.is_int())
                       total += item.as_int();
                   ws.yield(info.request_id, {total});
                 });
```

**Subscribing to a topic**

```c++
session->subscribe("random_number", {},
                   [](wampcc::wamp_session&, subscribed_info info) {
                     std::cout << "subscribed "
                               << (info ? "ok" : "failed")
                               << std::endl;
                   },
                   [](wampcc::wamp_session&, event_info info) {
                     for (auto& x : info.args.args_list)
                       std::cout << "got update: " << x << " ";
                     std::cout << std::endl;
                   });
```

**Publishing to a topic**
```c++
int random_variable = std::rand();
session->publish("random_number", {}, {{random_variable}, {}});
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

An individual RPC is provided by defining the realm & name through which it can
be called by a WAMP session, together with the lambda function which does the
actual work of generating a call result.

```c++
router.callable(
  "default_realm", "greeting",
  [](wamp_router&, wamp_session& caller, call_info info) {
    caller.result(info.request_id, {"hello"});
  });
```

The complete listing for these examples can be found at:

 - [demo_embedded_router.cc](https://github.com/darrenjs/wampcc/blob/master/examples/basic/demo_embedded_router.cc)
 - [demo_client.cc](https://github.com/darrenjs/wampcc/blob/master/examples/basic/demo_client.cc)


## Building wampcc -- Linux

Building *wampcc* involves several steps, including: installation of build tools; building the dependent libraries; obtaining the source; and source configuration.

**Setting up build tools**

*wampcc* can be built on Linux using either autotools, or cmake.  The latter is particularly useful for integration with IDE's, such as clion.

Building on Linux presumes that some essential programs are available, including:

- git
- autoconf (if using autotools approach)
- cmake (if using cmake approach)
- g++
- make
- wget
- libtool
- libssh headers & libraries

*wampcc* was developed on *xubuntu* and on this system these tools can be installed using the command:

```bash
sudo apt-get install cmake git autoconf gcc g++ make wget libtool libssl-dev
```

**Building dependent libraries**

*wampcc* requires that the C libraries *libuv* and *jansson* have already been built and installed.  The location of these libraries must be provided during the *wampcc* source configuration step.

**Obtaining the source**

The latest version of *wampcc* can be downloaded from github using:

```bash
git clone https://github.com/darrenjs/wampcc.git
```

This will fetch the source files directly from github and place them in a folder
named `wampcc/`.


Some third party code is directly integrated into `wampcc`, and are compiled
alongside `wampcc` source code.  For convenience these are stored in the
`3rdparty` folder; no additional download step is required to obtain them.

**Autotools approach**

Taking the autotools approach, if building from the git sources the `configure` script must be first generated.  An included helper script can do this:

```bash
./scripts/autotools_setup.sh
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

**CMake approach**

*wampcc* can also be built using cmake.  The following instructions show how to
 use cmake to set up a command line build.

The preferred approach is to create a separate build folder outside of the
source tree.  In this example the build folder is
`/var/tmp/wmampcc_cmake_build`.

```bash
mkdir -p /var/tmp/wmampcc_cmake_build
cd /var/tmp/wmampcc_cmake_build
```

Next is the invocation of the `cmake` program to generate the makefiles.  This
tells cmake where to find the *libuv* and *jansson* libraries, where to install
the built targets, and where to find the *wampcc* source. The paths in this
example need to be replaced with paths specific to your system. This command
should be invoked from within the build folder.

```bash
cmake --verbose \
-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
-DCMAKE_BUILD_TYPE=Release \
-DLIBUV_DIR=/opt/libuv-1.10.2 \
-DJANSSON_DIR=/opt/jansson-2.10 \
-DCMAKE_INSTALL_PREFIX=/var/tmp/wampcc_install \
/var/tmp/wampcc_src
```

If *libuv* and *jansson* are already installed on your system, rather than being
separately built and provided, cmake can instead be configured to find and use
them, simply by omitting the corresponding variables:

```bash
cmake -DCMAKE_INSTALL_PREFIX=/var/tmp/wampcc_install /var/tmp/wampcc_src
```

Following successful generation of the make files, *wampcc* can be built using
make:

```bash
make
```

## Setting up - Windows

The following steps assume that you wish to install `wampcc` and the
required dependencies in `C:\build`. You may modify this by 
replacing `C:\build` with the path of your choice.

The dependecies are build in Release and `wampcc` in Debug. You may change 
these by modifying the `-DCMAKE_BUILD_TYPE` CMake argument.

It's assumed that you are using Visual Studio and have NMake installed 
(which comes with Visual Studio).

### Setting up Windows build tools

This step compiles and sets up the dependencies. 

1. Download and install CMake.
2. Download and install OpenSSL, including the
   headers. [Here](https://slproweb.com/products/Win32OpenSSL.html) is a
   good source of compiled binaries.
3. Download and unzip `jansson` and `libuv` source files.
4. Run the correct Visual Studio developer command prompt for the architecture 
   (e.g. x86/x64) that you are compiling for. The architecture must match that 
   of the OpenSSL libraries that you just installed.
   
   For example, if you installed the 64-bit version of OpenSSL and are
   using Visual Studio 2017, then you must use 'x64 Native Tools Command
   Prompt for VS2017'. This should be available from the Visual Studio folder 
   in the Start menu.
5. Go inside the `jansson` source folder, and run:

   ```
   mkdir build
   cd build
   cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=C:\build\jansson ..
   nmake
   nmake install
   ```
   
7. Go inside the `libuv` source folder, and run:

   ```
   mkdir build
   cd build
   cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ..
   nmake
   mkdir C:\build\libuv
   mkdir C:\build\libuv\lib
   copy uv.dll C:\build\libuv\lib
   copy uv.lib C:\build\libuv\lib
   mkdir C:\build\libuv\include
   xcopy /E ..\include C:\build\libuv\include
   ```
   
   Note that `libuv` does not provide an `install` target, hence why we had to
   manually copy the files over.

### Setting up wampcc

1. Download a copy of wampcc
2. Run Visual Studio command line tools as described in the previous section
3. Run

   ```
   mkdir build
   cd build
   cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=C:\build\wampcc -DJANSSON_DIR=C:\build\jansson -DLIBUV_DIR=c:\build\libuv  -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64" ..
   nmake
   ```
   
   If the paths to `libuv`, `jansson` or OpenSSL are different then you will 
   need to change the appropriate parameters in the command above.
   
4. If you wish to install `wampcc`, you can do so:

   ```
   nmake install
   ```
  
