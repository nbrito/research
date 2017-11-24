#  Simple Makefile for the COPS documentation
#
#	make all	    -- makes everything
#	make <doc-name> -- make a given doc
DOCS	   = COPS.report.ms suid.man.ms kuang.man.ms
MAN        = cops.1 cron.chk.1 dev.chk.1 group.chk.1 is_able.chk.1 \
             passwd.chk.1 is_able.1 home.chk.1 user.chk.1 pass.chk.1 \
             root.chk.1 rc.chk.1 pass_diff.chk.1 misc.chk.1
DOC_SOURCE = COPS.report suid.man kuang.man cops cron.chk dev.chk is_able.chk \
             dir.chk file.chk group.chk passwd.chk is_able home.chk \
             user.chk pass.chk root.chk rc.chk pass_diff.chk misc.chk
ROFFLAGS   = -ms

#
# Where the programs are....
#
NROFF=/usr/bin/nroff
RM=/bin/rm -f

# make all
all:	$(DOCS) $(MAN)

clean:
	$(RM) $(DOCS) $(MAN)

# 'roff out those docs
COPS.report.ms: COPS.report
	$(NROFF) $(ROFFLAGS) COPS.report > COPS.report.ms

kuang.man.ms: kuang.man
	$(NROFF) $(ROFFLAGS) kuang.man > kuang.man.ms

suid.man.ms: suid.man
	$(NROFF) $(ROFFLAGS) suid.man > suid.man.ms

cops.1: cops
	$(NROFF) -man cops > cops.1

cron.chk.1: cron.chk
	$(NROFF) -man cron.chk > cron.chk.1

dev.chk.1: dev.chk
	$(NROFF) -man dev.chk > dev.chk.1

dir.chk.1: dir.chk
	$(NROFF) -man dir.chk > dir.chk.1

file.chk.1: file.chk
	$(NROFF) -man file.chk > file.chk.1

group.chk.1: group.chk
	$(NROFF) -man group.chk > group.chk.1

passwd.chk.1: passwd.chk
	$(NROFF) -man passwd.chk > passwd.chk.1

pass.chk.1: pass.chk
	$(NROFF) -man pass.chk > pass.chk.1

is_able.1: is_able
	$(NROFF) -man is_able > is_able.1

is_able.chk.1: is_able.chk
	$(NROFF) -man is_able.chk > is_able.chk.1

home.chk.1: home.chk
	$(NROFF) -man home.chk > home.chk.1

user.chk.1: user.chk
	$(NROFF) -man user.chk > user.chk.1

root.chk.1: root.chk
	$(NROFF) -man root.chk > root.chk.1

rc.chk.1: rc.chk
	$(NROFF) -man rc.chk > rc.chk.1

pass_diff.chk.1: pass_diff.chk
	$(NROFF) -man pass_diff.chk > pass_diff.chk.1

misc.chk.1: misc.chk
	$(NROFF) -man misc.chk > misc.chk.1

# the end
