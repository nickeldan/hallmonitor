============
Hall Monitor
============

:Author: Daniel Walker
:Version: 0.1.2
:Date: 2022-01-15

Overview
========

Hall Monitor detects and logs TCP SYN packets over a local network.  It is available as both a standalone
executable as well as a library which can be used in other projects.

API
===

The library centers around use of a **hamoDispatcher** object, defined in hamo/hamo.h.  A dispatcher can be
initialized by

.. code-block:: c

    hamoDispatcher dispatcher = HAMO_DISPATCHER_INIT;

Its resources can be released by

.. code-block:: c

    hamoDispatcherFree(&dispatcher);

Monitoring network devices
--------------------------

You can add monitoring of a network device to a dispatcher with the **hamoPcapAdd** function.  Its signature
is

.. code-block:: c

    int
    hamoPcapAdd(hamoDispatcher *dispatcher, const char *device, const hamoArray *whitelist);

We will discuss whitelisting later.  For now, you can set it to **NULL**.  For this function, **device**
refers to a network device, such as "any" or "en0".  The function returns **HAMO_RET_OK** if successful and
an error code otherwise (defined in hamo/definitions.h).  At the moment, monitoring of a network device is
only supported if its link-layer protocol is either Ethernet or the Linux cooked header protocol.

**hamoPcapAdd** may be called repeatedly in order to add multiple devices to the dispatcher.

Journaling
----------

Once a packet is captured and parsed, the dispatcher has to know what to do with it.  To that end, you must
register at least one **hamoJournaler** with the dispatcher.  Its definition (provided by hamo/journal.h) is

.. code-block:: c

    typedef struct hamoJournaler {
        void (*func)(void *, const hamoRecord *);
        void *user;
    } hamoJournaler;

where **hamoRecord** is defined by the same file as

.. code-block:: c

    typedef struct hamoRecord {
        struct timeval timestamp;
        uint16_t sport;
        uint16_t dport;
        uint8_t source_address[16];
        uint8_t destination_address[16];
        uint8_t tcp_flags;
        unsigned int ipv6 : 1;
    } hamoRecord;

A journaler can be added to a dispatcher by

.. code-block:: c

    hamoArrayAppend(&dispatcher.journalers, &journaler);

This function returns **HAMO_RET_OK** if successful and an error code otherwise.

For each packet that is captured and parsed, a **hamoRecord** will be created and passed to each registered
journaler's **func** field with the **user** field passed as the first argument.

Listening for packets
---------------------

Once all of your devices and journalers have been added, you can dispatch the dispatcher via the
**hamoPcapDispatch** function.  Its signature is

.. code-block:: c

    int
    hamoPcapDispatch(const hamoDispatcher *dispatcher, int timeout, unsigned int *count);

This function will wait on all of its registered network devices until at least one of them has packets to
capture or the timer (measured in seconds) expires (set **timeout** to -1 to wait indefinitely).  You should
be aware that a device may be ready for reading but have no packets which satisfy the BPF and thus none of
the journalers will be called.  This function returns **HAMO_RET_OK** if successful and an error code
otherwise.

If **count** is not **NULL**, then the referenced integer will be increased (meaning you need to initialize
it yourself) by the number of packets successfully captured and parsed.

To be clear, only packets which are completely internal to the device's network will be captured.  Also, at
this moment, the capturing of IPv6 packets is not supported.

Whitelisting
------------

You can whitelist certain types of packets.  This alters the BPF so that the journalers won't be called on
such packets.  A whitelist can be created by including hamo/whitelist.h and declaring

.. code-block:: c

    hamoArray whitelist = HAMO_ARRAY(hamoWhitelistEntry);

A whitelist can be cleared by

.. code-block:: c

    hamoArrayFree(&whitelist);

There are two ways to add an entry to a whitelist.  The first is by filling out an entry manually and
appending it to the array.  An entry is defined by

.. code-block:: c

    typedef struct hamoWhitelistEntry {
        uint16_t port;
        char saddr[INET6_ADDRSTRLEN];
        char daddr[INET6_ADDRSTRLEN];
    } hamoWhitelistEntry;

Each field, if set, represents a feature that a packet must meet in order to be whitelisted.  **saddr** and
**daddr**, the source and destination IP addresses, respectively, are considered unset if their first
character **'\0'**.  **port** is considered unset if it is 0.  At least one field must be set.  For example,
if **saddr** is set to "1.2.3.4" and **port** is set to 8080, then any packet sent from 1.2.3.4 where either
the source or destination port is 8080 will be whitelisted.

If both **saddr** and **daddr** are set, then they must obviously be of the same IP version.

An entry is appended to the whitelist by

.. code-block:: c

    hamoArrayAppend(&whitelist, &entry);

You can also read whitelist entries from a file and append them in bulk to a whitelist.  Each line of the
file must contain three comma-separated fields.  The first field specifies the source IP address, the second
the destination address, and the third the port number.  Fields can be left empty.  For example,
"1.2.3.4,,8080" is a valid entry.  The line must contain no whitespace other than a line break or carriage
return.  A line can be commented out by putting a **#** at the beginning.  Empty lines are also acceptable.

The file can be loaded into a whitelist by using the **hamoWhitelistLoad** function.  Its signature is

.. code-block:: c

    int
    hamoWhitelistLoad(FILE *file, hamoArray *whitelist);

It returns **HAMO_RET_OK** if successful and an error code otherwise.

You can free a whitelist by

.. code-block:: c

    hamoArrayFree(&whitelist);

Logging
-------

Optional logging is provided by the `Vanilla Squad`_ library.  If you want to enable Hall Monitor's logging
messages, use **vasqLoggerCreate** (see Vanilla Squad's documentation) with **hamo_logger** (provided by
hamo/definitions.h).

.. _Vanilla Squad: https://github.com/nickeldan/vanilla_squad

Executable
==========

The build process (see below), in addition to shared and static libraries, also builds an executable called
"hamo".  Several command-line options are available:

- -d <network_device>: Sets a network device to be monitored.  This option can be used more than once.  If no devices are added, then the "any" device will be used.
- -w <whitelist_file>: Loads whitelist entries from a file.  This option can be used more than once.
- -v: Enable verbose logging.
- -h: Show usage information.

The executable runs **hamoPcapDispatch** on a loop until a **SIGINT** is received.  Captured packets are
logged to the screen.

Building
========

Building of the executable and libraries (shared and static) is done with make.  You can pass "debug=yes" to
the make invocation in order to disable optimization and add debugging symbols.

You can also include the Hall Monitor library in a larger project by including make.mk.  Before doing so,
however, the **HAMO_DIR** variable must be set to the location of the Hall Monitor directory.  You can also
tell make where to place the shared and static libraries by defining the **HAMO_LIB_DIR** variable (defaults
to **HAMO_DIR**).

make.mk adds a target to the variable **CLEAN_TARGETS**.  This is so that implementing

.. code-block:: make

    clean: $(CLEAN_TARGETS)
        ...

in your project's Makefile will cause Hall Monitor to be cleaned up as well.  **CLEAN_TARGETS** should be
added to **.PHONY** if you're using GNU make.

make.mk defines the variables **HAMO_SHARED_LIBRARY** and **HAMO_STATIC_LIBRARY** which contain the paths of
the specified libraries.  It also defines the **HAMO_INCLUDE_FLAGS** variable which contains all of the
**-I** directives to be added to **CFLAGS**.

Since Hall Monitor has a dependency upon Vanilla Squad, make.mk includes Vanilla Squad's make.mk.  This also
defines variables like **VASQ_SHARED_LIBRARY** and **VASQ_STATIC_LIBRARY**.  There is also a **VASQ_LIB_DIR**
variable you can set which functions similarly to **HAMO_LIB_DIR**.

To be clear, make.mk will not cause the hamo executable to be built.

Configuration
-------------

By default, Hall Monitor allocates 512 characters (which includes the null terminator) for the BPF which is
applied to a capture handle.  You can change this limit at compilation time by setting the
**HAMO_BPF_MAX_SIZE** preprocessor variable.
