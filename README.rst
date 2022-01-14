============
Hall Monitor
============

:Author: Daniel Walker
:Version: 0.0.1
:Date: 2022-01-13

Overview
========

Hall Monitor detects and logs TCP SYN packets over a local network.  It is available as both a standalone
executable as well as a library which can be used in other projects.

API
===

The library centers around use of a **hamoDispatcher** object, defined in hamo/capture.h.  A dispatcher can
be initialized by

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
register at least one **hamoJournaler** with the dispatcher (see hamo/journal.h for the definition).  One of
the fields of the journaler is a pointer to a function which will be called for every packet that is
captured.

A journaler can be added to a dispatcher by

.. code-block:: c

    hamoArrayAppend(&dispatcher.journalers, &journaler);

This function returns **HAMO_RET_OK** if successful and an error code otherwise.

Listening for packets
---------------------

Once all of your devices and journalers have been added, you can dispatch the dispatcher via the
**hamoPcapDispatch** function.  Its signature is

.. code-block:: c

    int
    hamoPcapDispatch(const hamoDispatcher *dispatcher, int timeout);

This function will wait on all of its registered network devices until at least one of them has packets to
capture or the timer expires (set **timeout** to -1 to wait indefinitely).  You should be aware that a
device may be ready for reading but have no packets which satisfy the BPF and thus none of the journalers
will be called.  This function returns **HAMO_RET_OK** if successful and an error code otherwise.

To be clear, only packets which are completely internal to the device's network will be captured.  Also, at
this moment, the capturing of IPv6 packets is not supported.

Whitelisting
------------

You can whitelist certain types of events.  This alters the BPF so that the journalers won't be called on
such packets.  A whitelist can be created by including hamo/whitelist.h and declaring

.. code-block:: c

    hamoArray whitelist = HAMO_ARRAY(hamoWhitelistEntry);

A whitelist's entries can be freed by

.. code-block:: c

    hamoArrayFree(&whitelist);

There are two ways to add an entry to a whitelist.  The first is by filling out an entry manually and
appending it to the array.  An entry is defined by

.. code-block:: c

    typedef struct hamoWhitelistEntry {
        char saddr[INET6_ADDRSTRLEN];
        char daddr[INET6_ADDRSTRLEN];
        uint16_t port;
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
