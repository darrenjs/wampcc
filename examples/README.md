# Examples

## Building

To build all of the programs that live under the examples/ directory you will need to first define some environment variables which describe where wampcc and its dependent libraries have been installed, and then issue the `make` command.

If you try to compile before setting these variables you'll get an error like :

```console
makefile:9: *** WAMPCC_HOME undefined - set WAMPCC_HOME to where wampcc was make-installed. Stop.
```

The following is the list of environment variables which must be defined:

- `WAMPCC_HOME` - location of wampcc installation
- `LIBUV_HOME`  - location of libuv installation
- `JANSSON_HOME` - location of jansson installation

For example, if each library has been built and installed under `/opt` then
appropriate values and Linux commands (for a _bash_ shell) would be:

```console
export WAMPCC_HOME=/opt/wampcc-1.0
export LIBUV_HOME=/opt/libuv-1.10.2
export JANSSON_HOME=/opt/jansson-2.7
```

You should now be able to compile all examples under each sub-directory by running `make`.

## Running

Running the examples requires that your shell has `LD_LIBRARY_PATH` set appropriately, so that it can locate the shared libraries that wampcc links to. It is also useful to update your `PATH` to include the `admin` binary that is included with wampcc:


```console
for path in  "$WAMPCC_HOME"  "$LIBUV_HOME"  "$JANSSON_HOME" ; do
  export LD_LIBRARY_PATH="$path"/lib:"$LD_LIBRARY_PATH"
done

export PATH="$WAMPCC_HOME"/bin:"$PATH"
```


