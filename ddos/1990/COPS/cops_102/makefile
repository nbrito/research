#  Simple Makefile for the COPS system; compiles, and chmods 
# the programs.
#
#	make all	    -- makes everything
#	make install	    -- puts things in their place
#	make <program_name> -- make a given program
INSTALL_DIR= sun

EXECUTABLE = home.chk user.chk pass.chk is_writable crc crc_check \
	     addto clearfiles filewriters members tilde is_able
C_SRC      = home.chk.c user.chk.c is_able.c pass.c is_something.c \
	     addto.c clearfiles.c filewriters.c members.c tilde.c \
	     crc.c crc_check.c
SHELL_PROGS= chk_strings root.chk dev.chk cron.chk is_able.chk \
	     cops group.chk rc.chk passwd.chk ftp.chk crc.chk \
	     misc.chk suid.chk kuang init_kuang reconfig res_diff
SUPPORT    = is_able.lst stop.sample crc_list
CFLAGS     = -O
#  Certain systems need to uncomment this to compile the pass.chk; Xenix,
# some SysV:
# BRAINDEADFLAGS = -lcrypt

#
# Where the programs are....
#
CHMOD=/bin/chmod
TEST=/bin/test
MKDIR=/bin/mkdir
CP=/bin/cp
CC=/bin/cc
RM=/bin/rm

# make all
all:	$(EXECUTABLE)
	$(CHMOD) 700 $(SHELL_PROGS)

# hammer the binaries and formatted docs
clean:
	$(RM) -f $(EXECUTABLE)
	cd docs; make clean

# make the documentation
man:
	cd docs; make

# make a dir and shove everything in the proper place
install:
	-if $(TEST) ! -d $(INSTALL_DIR) ; then mkdir $(INSTALL_DIR) ; fi
	$(CP) $(EXECUTABLE) $(SHELL_PROGS) $(SUPPORT) $(INSTALL_DIR)

# make the programs
addto: src/addto.c
	$(CC) $(CFLAGS) -o addto src/addto.c

clearfiles: src/clearfiles.c
	$(CC) $(CFLAGS) -o clearfiles src/clearfiles.c

filewriters: src/filewriters.c
	$(CC) $(CFLAGS) -o filewriters src/filewriters.c

members: src/members.c
	$(CC) $(CFLAGS) -o members src/members.c

home.chk: src/home.chk.c
	$(CC) $(CFLAGS) -o home.chk src/home.chk.c

user.chk: src/user.chk.c
	$(CC) $(CFLAGS) -o user.chk src/user.chk.c

is_able: src/is_able.c
	$(CC) $(CFLAGS) -o is_able src/is_able.c

is_writable: src/is_something.c
	$(CC) $(CFLAGS) -DWRITABLE -o is_writable src/is_something.c

pass.chk: src/pass.c
	$(CC) $(CFLAGS) -o pass.chk src/pass.c $(BRAINDEADFLAGS)

tilde: src/tilde.c
	$(CC) $(CFLAGS) -o tilde src/tilde.c

crc: src/crc.c
	$(CC) $(CFLAGS) -o crc src/crc.c

crc_check: src/crc_check.c
	$(CC) $(CFLAGS) -o crc_check src/crc_check.c

# the end
