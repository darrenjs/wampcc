# Examples

After wampcc has been successfully compiled and installed (using `make install`) these example programs can be built and run to demonstrate basic WAMP functionality.

## Building

To build the examples you must first define a few environment variables which point to where wampcc and its dependent libraries have been installed, and then run `make -f examples.makefile`.

If you try to compile before setting these variables you'll see an error like:

```
makefile:9: *** WAMPCC_HOME undefined - set WAMPCC_HOME to where wampcc was make-installed. Stop.
```

These are the environment variables which must be defined:

- `WAMPCC_HOME` - location of wampcc installation
- `LIBUV_HOME`  - location of libuv installation
- `JANSSON_HOME` - location of jansson installation

For example, if each library has been built and installed under `/opt` then the appropriate Linux commands (for a _bash_ shell) might be:

```bash
export WAMPCC_HOME=/opt/wampcc-1.0
export LIBUV_HOME=/opt/libuv-1.10.2
export JANSSON_HOME=/opt/jansson-2.7
```

You should now be able to compile all examples by running `make`.

```bash
cd examples
make -f examples.makefile
```

## Running

Running the example programs requires that your shell has `LD_LIBRARY_PATH` set appropriately, so that the shared libraries linked-to by wampcc can be located. It is also useful to update your `PATH` to include the `admin` binary that is included with wampcc:

```bash
for path in  "$WAMPCC_HOME"  "$LIBUV_HOME"  "$JANSSON_HOME" ; do
  export LD_LIBRARY_PATH="$path"/lib:"$LD_LIBRARY_PATH"
done

export PATH="$WAMPCC_HOME"/bin:"$PATH"
```

## Embedded router and RPC invocation

After the examples are built we can run the `basic_embedded_router` program together with the `admin` utility to demonstrate basic WAMP RPC functionality.

Start the embedded router example by providing a port number on which it will listen for new connections:

```bash
basic/basic_embedded_router 55555
```

If it's able to bind to the port then the following output will appear:

```
20170311-18:48:24.306394 20045  INFO listening on 55555
20170311-18:48:24.306807 20045  INFO procedure added, 1, default_realm::greeting
20170311-18:48:24.306899 20045  INFO procedure added, 2, default_realm::pid
20170311-18:48:24.306940 20045  INFO procedure added, 3, default_realm::random_string
20170311-18:48:24.306978 20045  INFO procedure added, 4, default_realm::kill
```
This shows the names of the RPCs that the program has registered.

An RPC can be called using wampcc's `admin` program:

```bash
admin 127.0.0.1 55555 -c greeting
```

Here the `-c` option means call the RPC named `greeting`, and the second line is the output of the RPC.


