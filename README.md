# jalson
C++ abstraction library for JSON implementations

There aready exists a large number of JSON implementation for C/C++, so why the
need for another?

ABSTRACTION / DNAGERS

One downside of having so many JSON libraries avaiable is that the one you
chosse for your next project might become one day become obselete.  If that
happens, an dexsting JSON library will hae to be replaced for another. This will
typically not be an easy or triveila  taks, speciiclal because the object model
o fthe orignak JSOB library might have found is wasy through-out many parts of
the end applicatin code.

This is where jalson comes in.  The idea is that it can be used to wrap the
public interface of other json implementation.  The user application is
isoloated from the pulbic api, and data model, of the actual json librares. Thus
sht so that while they can be used for their parsing / encoding features
parse;but their API, interms of lcasses etc, does not get exposed to the
application.  Then if a json impl needs to be changed, it can be done so entirel
ywith inthe jalson layer, and so ugely reducing the distruptio nfor the end
application

DETAILS

So jalson is not a json parser / building.  It offers an object model for
buiding and using JSON data; and abstracts away the underling details fo the
parsing code (which is deferring to the implementaion).

So specifically, jalson provides an object model of a JSON document, and wraps
an underlying JSON imolementation to provide encoding and decodier.

In addtion, jalson is designed using the following guidelines:

* STL based  say: objecs & arrary are just stl contains. map  /vector / string

* intuituve inteface  ii no attempt to replicate python syntax, or JQiery
  syunatcm

* minimally complete -- doesnt offer unnesary details; the motivated agian is to
  have it easilyl to integrate into code, and bty being minimal, there is less
  for your code to rely upon.

IMPLEMETATONS SUPPORTED (VENDORS)

SAY: currently jalson comes with support for the jansson JSON library; and that
can serve as an example of wrapping other JSON libraries

EXAMPLE USAGE

TODO: get an eample iml here:

* print vendor details
* build a simple object
* print

show how to link

TODO: need to show some example os building and decoding.

SOURCE CONFIGURATION

say autotools are used as the build system, ie, the configure script must be
called to generate the makefiles (note that f starting a git checkout, the
configure script needs to be first generated, using the autotools_setup.sh
script).

During invokcation of the configure script, jaslon must be told which vendor
implementation it will used.  Eg., in this example, the jalson source is being
configured to use a version of jansson which has previously been built and
installed to a particular location; jalson is also being confgured so that it
gets installed into a custom directory /opt/jalson/1.0 :

    configure  --prefix=/opt/jalson/1.0 --with-janson=/opt/jansson-2.7

Failure to specify a vendor implmeentation will lead to configure error:

    configure: error: You have not configured a JSON implemention vendor.
