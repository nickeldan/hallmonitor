============
Hall Monitor
============

:Author: Daniel Walker

Version 0.0.1 was release on ???.

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

    hamoWhitelistFree(&whitelist);

There are two ways to add an entry to a whitelist.  The first is by creating an entry individually and
appending it to the array.  To create an array, use the function

.. code-block:: c

    int
    hamoWhitelistEntryParse(const char *string, hamoWhitelistEntry *entry);

**string** is a null-terminated string containing three comma-separated fields (no spaces).  The first field
specifies a source IP address, the second a destination address, and the third a port number.  Any field can
be left empty but at least one field must be filled.  For example, the string "1.2.3.4,,22" would block any
packet coming from 1.2.3.4 that has either a source or destination port of 22.

**hamoWhitelistEntryParse** returns **HAMO_RET_OK** if successful and an error code otherwise.  You can free
an entry's resources by

.. code-block:: c

    hamoWhitelistEntryFree(&entry);

You can add an entry to a whitelist by

.. code-block:: c

    hamoArrayAppend(&whitelist, &entry);

**hamoArrayAppend** returns **HAMO_RET_OK** and an error code otherwise.  If this function succeeds, then you
must consider **entry** to be no longer usable.  Don't even call **hamoWhitelistEntryFree** on it.

You can also add entries to a whitelist from a file by the function

.. code-block:: c

    int
    hamoWhitelistLoad(FILE *file, hamoArray *whitelist);

This function returns **HAMO_RET_OK** and an error code otherwise.  The contents of the file must have
enries on separate lines with no whitespace but line breaks.  You can cause a line to be ignored by putting a
"#" as the first character of the line.
