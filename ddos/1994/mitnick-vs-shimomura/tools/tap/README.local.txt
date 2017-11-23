#       @(#)README	1.24 3/22/92
#
############################################################################
#   This is the STREAMS tap module/driver pseudo-device. aka WATER-WORKS
############################################################################
#
# runs on:
#		sun3/50 4.1.1
#		sun4/75 4.1.2
#

COPYRIGHT:
        - you want COPYRIGHT ? i will give you COPYRIGHT.
          Copyright (c) 1992 Simon Ney -- All Rights Reserved


                                ---------------


DESCRIPTION:
        - the device is a monitor/manipulator for other STREAMS-devices
          such as standard UNIX control-terminals.

        - this driver is a kernel-loadable-module. (==>no reboot required)

        - it is a combination of a STREAMS-module and a STREAMS-driver.

                tap     - is the name of the pushable/poppable STREAMS-modules.
                tapc*   - are the names of the STREAMS-driver nodes (special
                          files)..

        - the tap-modules must first manually pushed/popped on each stream
          to be monitored or manipulated, independ if the tapc-driver is
          open or not. see also ioctl(fd,I_PUSH|I_POP,"tap").

        - the first module pushed become the id 0, the second 1, and so on...
          if any of these modules are popped the next pushed will become
          the old id of the previous popped module. the module ids are
          always unique, and are assigned first fit.
          the maximal number of tap-modules pushed is NTAP (see tap.h).

        - a pushed-tap-module act as NULL-streams-MODULE (pass data from below
          to above and data from above to below) unless it is connected with
          the tapc-driver.

        - now if a minor device of the tapc-driver is opened the minor
          device-number is used to check if such tap-module is pushed
          (minor number = tap-id). if no such module id is present a
          ENETUNREACH (Network is unreachable) error is returned by open().
          if the module id (minor device number) can be found, a connection
          to the pushed-tap-module is established.

        - all minor-device-nodes can only open by one user at a time,
          the second open() on the same minor device returns a EBUSY (Device
          busy) error.

        - if the open() has the O_NDELAY flag set a TAP_REVERSE flag
          is internal set in the driver. the TAP_REVERSE flag can only
          set by the super-user, a non-superuser open() returns a EACCES
          (Permission denied) error.

        - now data can be received/send from/to the pushed-tap-module
          with read() and write().

        - if the TAP_REVERSE flag is not set, data received by the tap-module
          from the above modules/streamshead (upper-stream) is duplicated
          and send to the read-side of the tapc-driver, and can be read by
          the user process that opened the tapc-driver.
          data written with write() by the process that opened the tapc-driver
          are send to modules/streamshead above the tap-module (upper-stream).

        - if the TAP_REVERSE flag is set, data received by the tap-module
          from the module/driver below the tap-module (lower-stream) is
          duplicated and send to the read-side of the tapc-driver, and can
          be read by the user process that opened the tapc-driver.
          data written with write() by the process that opened the tapc-driver
          are send to the modules/driver below the tap-module (lower-stream).

        - if the tapc-driver is closed the messages are not dupclicated as
          long as the tapc-driver is re-open. (the tap-modules remains
          pushed)

        - if data is written by the tapc-driver and the connected module
          was popped a ENETCONNRESET (Connection reset by peer) error is
          return to the write().

        - if the stream that has the tap-module pushed is closed, all modules
          on this stream are popped by the system. but there is a configuration
          option in sunos to autopush any modules on open() (that's different
          in a SYSV environment).


                                ---------------


FIGURES:
       (USER PROCESS)           (BIG BROTHER)
         (csh,vi)           (tapmon)    (tapmon -r)  (tip/cu/uucico)
         /dev/ttya         /dev/tapc0   /dev/tapc1      /dev/cua1
--------------------------------------------------------------------------------
        |ttya HEAD |       |tapc HEAD|  |tapc HEAD|   |cua1 HEAD |
        +----------+       +---------+  +---------+   +----------+
             | ^              | ^          | ^             | ^
             | |              | |          | |             | |
             | |           ...........  ...........        | |
             | |           . MORE    .  . MORE    .        | |
             | |           . MODULES .  . MODULES .        | |
             | |           ...........  ...........        | |
             | |              | |          | |             | |
             v |              v |          v |             | |
        ............       +---------+  +---------+   ............
        . MORE  (2).       |TAPC 0   |  |TAPC 1   |   . MORE (2) .
        . MODULES  .       |DRIVER   |  |DRIVER(1)|   . MODULES  .
        ............       +---------+  +---------+   ............
          (3)| ^(4)           | ^          | ^             | |         UPPER
             v |              | |          | |             v |         STREAMS
        +----------+          | |          | |        +----------+
        |    \ \   |          | |          | |        | TAP 1    |
        |     \ \--|<---------/ |          | \--------|\  MODULE |
        | TAP 0\---|------------/          \--------->| \  PUSHED|
        | MODULE   |                                  |\ \REVERSE|
        | PUSHED   |                                  | \ \ OPEN |
        |          |  <--- NORMAL       REVERSE--->   |  \ \     |
        +----------+                                  +----------+
             | ^                                       (4)| ^(3)        LOWER
             v |                                          v |           STREAMS
        ............                                  ............
        . MORE  (2).                                  . MORE     .
        . MODULES  .                                  . MODULES  .
        ............                                  ............
             | ^                                          | ^
             v |                                          v |
        +----------+                                  +----------+
        | zs DRIVER|                                  | zs DRIVER|
--------------------------------------------------------------------------------
    physical STREAMS device                      physical STREAMS device
         (terminal)                                    (modem)
         (intruder)                                (other systems)

                                        ----------
                                        (1) - opened by O_NDELAY from root
                                        (2) - e.g. ttcompat,ldterm,kb,ms,
                                                   slip,ax25,pf,nbuf
                                        (3) - duplicated streams
                                        (4) - multiplexed streams


NOTE: the ,,physical STREAMS device'' above shown can be any streams device
      e.g.:      /dev/{tty*,console,nit,tcp,loop,mux,mti,kbd,mouse,*CLONE*}
                (nit and tcp is a clone device !)
      slip cant monitored because itself pops all modules pushed.
      the only way is to modify sliplogin.c to push the tap module below
      the slip module.


                                ---------------



INSTALLATION:
        the current version has been tested under sunos 4.1.1 on a sun3/50
        and sunos 4.1.2 on a sun4/75. but i hope the version will run on any 
	sun with the loadable-driver /dev/vd,otherwise read the INSTALL file 
	and your STREAMS programming manual (the load of the pushable
	streams-module is done by hand on suns). if the modload(8) 
	fails or the use of the driver crashes the kernel let me know ...

        to make the kernel-loadable module and automatic load into the kernel
        type (as root);

                # make

        the tapmon(1)+streams(1) user-commands are created.(the streams(1)
        command can be used to push/pop other non-tap streams modules,the
         (1) is a TAP-driver application).
        a possible old tap-module is automatically unloaded if a new is loaded
        (after multiple make commands).  the device nodes (/dev/tapc*) are
        created as expected.



                                ---------------



SOME EXAMPLES:
        now login from ttya before continue (or pick a already opened
        pseudo-tty from the window-system (NOT the one you will enter
        the following commands))

                # streams -u tap < /dev/ttya
                # tapmon 0

        this push a tap-module on the already open /dev/ttya serial-tty and
        then start the monitor/manipulator. all data send to /dev/ttya are
        now duplicated to your standard output,and all data send by you are
        send as input to the process on ttya, thats the same as you are sit
        in front of ttya.
        type CTRL-_ to leave the tapmon.
        NOTE: after leaving tapmon the tap-streams-modules remains pushed.

        here an example output from ,,pstat -S'' while one tapmon is running:

                   LOC     WRQ       VNODE     DEVICE   PGRP SIGIO  FLAGS
                 f05461e    f05583c   f0cdb94  59,  0      0     0  R
                  Write side:
                    NAME      COUNT FLG    MINPS  MAXPS  HIWAT  LOWAT
                    strwhead      0            0      0      0      0
                    tapc          0  R         0    INF      0      0
                  Read side:
                    tapc          0  R         0    INF      0      0
                    strrhead      0  R         0    INF   5120   1024


                   LOC     WRQ       VNODE     DEVICE   PGRP SIGIO  FLAGS
                 f0543e0    f0550ec   f0cc9f4  12,  1    905     0
                  Write side:
                    NAME      COUNT FLG    MINPS  MAXPS  HIWAT  LOWAT
                    strwhead      0            0      0      0      0
                    tap           0  R         0    INF      0      0
                    ttcompat      0  R         0    INF    300    200
                    ldterm        0  R         0    INF      1      0
                    zs            0  R         0    INF   2048    128
                  Read side:
                    zs            0  R         0    INF   2048    128
                    ldterm        0  R         0    128    500    200
                    ttcompat      0  R         0    INF   2048    128
                    tap           0  R         0    INF      0      0
                    strrhead      0            0    INF    300    200


        the kernel-loadable-module can only unloaded by ./unload or by
        modunload(1) if all tap-modules are popped and the /dev/tapc* devices
        are closed (if you are not sure look in ,,pstat -S'' for the
        string "tap" ).

                # streams -o tap < /dev/ttya
                # ./unload

        this pops the previous pushed module and unloads the
        kernel-loadable-module from the kernel...

        NOTE: always use ./unload instead of modunload(8) because the Makefile
              keep track of the loaded kernel-modules !

        another example is (if you not already done the ./unload operation
        above,otherwise you must reload the tapc/tap driver with another
        ,,make''):

                # streams -o ttcompat -o ldterm \
                        -u tap -u ldterm -u ttcompat < /dev/ttya
                # tapmon 0

        now you can monitor direct above the physical device and below
        the ldterm module and can see the line-editing functions of
        the ldterm and ttcompat modules.
        also signals send by you, such as CTRL-C are processes by the
        ldterm and ttcompat modules and send as signal to the process
        as expected (in the former example not, a CTRL-C was send as
        input byte 0x03 to the user-process)

        here how to undo the last modules transaction:

                # streams -o ttcompat -o ldterm -o tap -u ldterm \
                        -u ttcompat < /dev/ttya

        NOTE: the order of ther streams(1) command is important (stack order).



                                ---------------


KERNEL CONFIG:
        if you want to link the tapc/tap device-driver permanently to /vmunix
        be sure not to define TAPVD (see Makefile) and to ignore tap.h
        (see tap.h). follow the steps in the ,,INSTALL'' file.


                                ---------------


KNOWN BUGS:
        - CLONE open are currently disabled because it may crash the kernel,
          after 7 modules are pushed and 7 tapmons (using clone open) started
          in backgroup then close the stream that has the 7 modules pushed,
          and then reconnected to the tapmons with csh ,fg'' command, the 7th
          ,,fg'' crash the sun3sunos4.1.1 kernel with the following message:
                                        ****
         ,,assertion failed: vp->v_stream, file: ../../os/str_io.c, line 3823''
         ,,panic: assertion failed''
                                        ****
          the kernel-backtrace shows than it was called from some kernel
          select(), thats the first function tapmon calls after the CLONE open.

         - if the BUG is fixed CLONE opens connects to the first unconnected
           module, and not the last pushed module!


                                ---------------


SECURITY NOTES:
        - the paranoid sysadmin must decide what permission he want to give to
          the /dev/tapc* devices (e.g. chmod 600 /dev/tapc*).
          the TAP_REVERSE mode can only be used by the super-user because
          it can be used to read clear text passwords during login-time and
          to get control of external devices such as modems and communication
          devices.

        - a typical LUSER can start ,,pstat -S'' to see if BIG BROTHER is
          watching...


                                ---------------


COMMENTS:
        - you can use TAP for education proposes if you push multiple
          tap-modules on a single stream or you can create BIG BROTHER trees,
          and make a UNIX alliance so that multiple users use the same
          shell,editor.... and can correct each other....or to help UNIX
          beginners....isnt it a some kind of human-neural-nets ?

        - the only problem is the possible wrong terminal-emulation *sigh*.
          but there is a universal-terminal-emulation under X, and the screen
          command from Oliver Laumann.

        - a MAN page is included in the next release.

        - i hope my english is funny...

        UNIX - is a registed bell of AT&T trademark laboratories.

--
Simon Ney -- neural@cs.tu-berlin.de -- simon@bbisun.uu.sub.org
