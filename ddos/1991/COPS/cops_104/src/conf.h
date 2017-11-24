/*
 * This program is copyright Alec Muffett 1991 except for some portions of
 * code in "crack-fcrypt.c" which are copyright Robert Baldwin, Icarus
 * Sparry and Alec Muffett.  The author(s) disclaims all responsibility or
 * liability with respect to it's usage or its effect upon hardware or
 * computer systems, and maintain copyright as set out in the "LICENCE"
 * document which accompanies distributions of Crack v4.0 and upwards.
 */

#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <signal.h>

/*
 * Undefine this symbol if your name is not Alec David Edward Muffett
 */

#undef DEVELOPMENT_VERSION

/*
 * define this symbol if you are on a system where you don't have the
 * strchr() function in your standard library (usually this means you are on
 * a BSD based system with no System Visms) but instead, you DO have the
 * equivalent index() function.
 */

#undef INDEX_NOT_STRCHR

/*
 * What bytesex is your machine ? Select one of the two below, if you have
 * some really weird machine - otherwise the program should be able to work
 * it out itself.
 */

#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

/* If you haven't selected one of the above options... */
#if	!defined(BIG_ENDIAN) && !defined(LITTLE_ENDIAN)

/* Can we work out if we are little endian ? */
#if 	defined(vax) || defined(ns32000) || defined(sun386) || \
	defined(i386) || defined(MIPSEL) || defined(BIT_ZERO_ON_RIGHT)
#define LITTLE_ENDIAN		/* YES */
#endif

/* Can we work out if we are bigendian ? */
#if	defined(sel) || defined(pyr) || defined(mc68000) || \
	defined(sparc) || defined(is68k) || defined(tahoe) || \
	defined(ibm032) || defined(ibm370) || defined(MIPSEB) || \
	defined(__convex__) || defined(hpux) || defined(apollo) || \
	defined (BIT_ZERO_ON_LEFT) || defined(m68k) || defined(m88k) || \
	defined(_IBMR2) || defined(AMIGA) /* yes, an Amiga A500... */
#define BIG_ENDIAN		/* YES */
#endif

/* end of trying to guess things */
#endif

/* are we schitzophrenic ? */
#if	defined(BIG_ENDIAN) && defined(LITTLE_ENDIAN)
ERROR_BAD_BIT_ORDER;		/* YES */
#endif

/* are we still ignorant ? */
#if	!defined(BIG_ENDIAN) && !defined(LITTLE_ENDIAN)
ERROR_NO_BIT_ORDER;		/* YES */
#endif


/*
 * define this if you have the macros _toupper() and _tolower(), which are
 * compatible with the un-intelligent K&R versions of the toupper() and
 * tolower() functions, and which do not test their input for validity.
 */

#undef FAST_TOCASE

/*
 * define this if you are on a Sys V type system with a uname() system call
 * AND YOU HAVE NO gethostname() - it fakes up a BSD gethostname() so you can
 * use CRACK_NETWORK; see crack-port.c
 */

#undef CRACK_UNAME

/*
 * define this if you want to search the first 1Kb segment of users
 * .plan/.project/.signature files for potential passwords
 */

#undef CRACK_DOTFILES

/*
 * define this if you are using fcrypt() - you might not want to if fcrypt()
 * doesn't work properly
 */

#define FCRYPT

/*
 * THE FOLLOWING SYMBOLS PERTAIN ONLY TO FCRYPT() USAGE
 */

/*
 * if defined, use builtin clearing in preference to using bzero(), for 4
 * or 8 byte long ints.  This is most preferable, and a Good Thing.  If it
 * is not defined, fcrypt() will try to use bzero().
 */

#define BUILTIN_CLEAR

/*
 * define this if you have a 4 byte "long_int" on RISC machines and want a
 * speedup - it should not hurt CISC machines either.  Do NOT define it on a
 * 8-byte int machine...
 */

#undef FDES_4BYTE

/*
 * define this if you are on a Cray or something with an 8-byte int, to
 * enable Matthew Kaufman's fcrypt fix.  I hope it works okay, cos I can't
 * test it - AEM.
 */

#undef FDES_8BYTE

/*
 * undef this if your compiler knows the fact that 6*x == x<<1 + x<<2
 */

#undef BRAINDEAD6

/* END OF THINGS THAT NEED CONFIGURING */

#ifdef DEVELOPMENT_VERSION
#define FDES_4BYTE
#endif
