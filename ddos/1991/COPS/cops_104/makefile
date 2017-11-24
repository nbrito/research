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
	     misc.chk suid.chk kuang init_kuang reconfig res_diff \
	     yp_pass.chk bug.chk bug.chk.aix bug.chk.apollo \
	     bug.chk.dec bug.chk.next bug.chk.sgi bug.chk.sun \
	     bug.chk.svr4 bug_cmp
SUPPORT    = is_able.lst suid.stop crc_list

#
CFLAGS     = -O
# sequents need "-lseq" as well... uncomment this if you're running on one:
# SEQFLAGS   = -lseq

#  Certain systems need to uncomment this to compile the pass.chk; Xenix,
# some SysV:
# BRAINDEADFLAGS = -lcrypt
#
# systems without rindex need to uncomment this:
# CRC_FLAG=-Dstrrchr=rindex

#
# Where the programs are....
#
CHMOD=/bin/chmod
TEST=/bin/test
MKDIR=/bin/mkdir
CP=/bin/cp
CC=/bin/cc
RM=/bin/rm

# make default
default:	$(EXECUTABLE)
		$(CHMOD) u+x $(SHELL_PROGS)

# make all
all:	$(EXECUTABLE)
	cd docs; make
	$(CHMOD) u+x $(SHELL_PROGS)

#  hammer the binaries and formatted docs; if compiled fcrypt stuff,
# will trash the *.o files, too.
clean:
	$(RM) -f $(EXECUTABLE) pass.o crack-fcrypt.o crack-lib.o
	cd docs; make clean

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

#   If fast crypt will work, comment the first CC line, uncomment
# the next two:
pass.chk: src/pass.c
	$(CC) $(CFLAGS) -o pass.chk src/pass.c $(BRAINDEADFLAGS)
# 	$(CC) $(CFLAGS) -Dcrypt=fcrypt -DFCRYPT -o pass.chk src/pass.c \
# 	src/crack-fcrypt.c src/crack-lib.c $(BRAINDEADFLAGS)

tilde: src/tilde.c
	$(CC) $(CFLAGS) -o tilde src/tilde.c

crc: src/crc.c
	$(CC) $(CFLAGS) -o crc src/crc.c $(SEQFLAGS)

crc_check: src/crc_check.c
	$(CC) $(CFLAGS) $(CRC_FLAG) -o crc_check src/crc_check.c $(SEQFLAGS)

# the end
