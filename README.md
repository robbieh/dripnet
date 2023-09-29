
Dripnet
=======

A Babashka script to show outgoing connection ports as drops on the terminal.

!["snapshot of dripnet running"](../../../raw/branch/dev/media/dripnet.png)

Usage
=====

Since this relies on `tcpdump` you need to have it installed and be able to run it without a password using `sudo`. Place a line like such in your `sudoers` file:
```
MYUSER ALL = NOPASSWD: /usr/bin/tcpudmp
```

Then invoke dripnet:
```
bb dripnet.clj $COLUMNS $LINES
```
