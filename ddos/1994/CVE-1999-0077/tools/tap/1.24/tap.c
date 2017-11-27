/*
 * tap streams-module/driver kernel-loadable-module, aka WATER-WORKS 
 * this is a combination of a STREAMS-module and a STREAMS-driver.
 *
 * Simon Ney -- neural@cs.tu-berlin.de -- simon@bbisun.uu.sub.org
 */

#include "tap.h"
#if    NTAP > 0
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/termio.h> /*XX*/
#ifdef TAPVD
#include <sys/conf.h>
#include <sun/vddrv.h>
#endif TAPVD

#ifndef lint
static	char sccsid[] = "@(#)tap.c	1.24 3/22/92";
#endif

/* 
 * --- DRIVER PART --- 
 */

#ifdef TAPVDDUAL
static struct module_info cminfo = { 0, "tapcvd", 0, INFPSZ, 0, 0 };
#else
static struct module_info cminfo = { 0, "tapc", 0, INFPSZ, 0, 0 };
#endif

static int tapcopen(), tapcrput(), tapcwput(), tapcclose();

static struct qinit crinit = {
    tapcrput, NULL, tapcopen, tapcclose, NULL, &cminfo, NULL
};

static struct qinit cwinit = {
    tapcwput, NULL, NULL, NULL, NULL, &cminfo, NULL
};

#ifdef TAPVD /* so we can have a permanent linked AND loadable version */
struct streamtab tapcvdinfo = { &crinit, &cwinit, NULL, NULL };
#else
struct streamtab tapcinfo = { &crinit, &cwinit, NULL, NULL };
#endif

/*
 * --- MODULE PART --- 
 */

#ifdef TAPVDDUAL
static struct module_info minfo = { 0, "tapvd", 0, INFPSZ, 0, 0 };
#else
static struct module_info minfo = { 0, "tap", 0, INFPSZ, 0, 0 };
#endif

static int tapopen(), taprput(), tapwput(), tapclose();

static struct qinit rinit = {
    taprput, NULL, tapopen, tapclose, NULL, &minfo, NULL
};

static struct qinit winit = {
    tapwput, NULL, NULL, NULL, NULL, &minfo, NULL
};

#ifdef TAPVD /* so we can have a permanent linked AND loadable version */
struct streamtab tapvdinfo = { &rinit, &winit, NULL, NULL };
#else
struct streamtab tapinfo = { &rinit, &winit, NULL, NULL };
#endif

/*
 * the ,,TAP device'' structure 
 */

struct tap {
	queue_t *tapdm_queue;	/* queue from driver to module (set by module)*/
	queue_t *tapmd_queue;	/* queue from module to driver (set by driver)*/
#define TAP_REVERSE	1	/* if set connect to lower side else upper */
	unsigned int tap_flags;	/* currently only the TAP_REVERSE flag */
};
static struct tap  tap_tap[NTAP];	/* static for now */
static int tap_cnt = NTAP;

/* 
 * --- KERNEL-LOADABLE-MODULE SUPPORT --- 
 */

#ifdef TAPVD
extern int nodev();

static struct cdevsw		tap_cdevsw = { 
	nodev, nodev, nodev, nodev, nodev, nodev, nodev, 0, 
	&tapcvdinfo, 0
};

static struct vdldrv tapvdldrv = {
	VDMAGIC_PSEUDO, "tapc/tap-1.24", 
	NULL,
#ifndef sun4c
	NULL, NULL, 0, 1,
#endif
	NULL, &tap_cdevsw, 0, 0	
};

/*
 * this is the pushable-STREAMS-module kernel-module-loader
 */
static	struct fmodsw *saved_fmp;

static struct fmodsw *loadfmodsw(name,str)
char *name;
struct streamtab *str;
{
	register struct fmodsw *fmp;
	register int i;
	extern struct fmodsw fmodsw[];
	extern int fmodcnt;

	fmp = fmodsw;
	for(i=0;i<fmodcnt;i++,fmp++){
		if(fmp->f_str==0){
			strcpy(fmp->f_name,name);
			fmp->f_str = str;
			return(fmp);
		}
	}
	printf("tap: loadfmodsw: no free slot for '%s'\n",name);
	return(0);
}

static unloadfmodsw(fmp)
	struct fmodsw *fmp;
{
	fmp->f_name[0] = '\0';
	fmp->f_str = 0;
}

/*
 * this is the driver entry point routine. the name of the default entry
 * point is xxxinit. it can be changed by using the "-entry" command to
 * modload.
 */

xxxinit(function_code,vdp,vdi,vds)
unsigned int function_code;
struct vddrv *vdp;
addr_t vdi;
struct vdstat *vds;
{
	register int i;
	register struct tap *tap;

	switch(function_code){
	case VDLOAD:
		if(saved_fmp){		/* ever occured */
			printf("tap: xxxinit:already loaded\n");
			return(ENXIO);
		}
#ifdef TAPVDDUAL
		if(!(saved_fmp=loadfmodsw("tapvd",&tapvdinfo))){
#else
		if(!(saved_fmp=loadfmodsw("tap",&tapvdinfo))){
#endif
			return(ENXIO);
		}
		vdp->vdd_vdtab = (struct vdlinkage *) &tapvdldrv;
		break;
	case VDUNLOAD:
		for(i=0,tap=tap_tap;i<tap_cnt;i++,tap++)
			if(tap->tapdm_queue||tap->tapmd_queue)
				return(EBUSY);	
		if(saved_fmp)
			unloadfmodsw(saved_fmp);
		break;
	case VDSTAT:
#ifdef TAPDEBUG
		for(i=0,tap=tap_tap;i<tap_cnt;i++,tap++)
			if(tap->tapdm_queue||tap->tapmd_queue)
				printf( "tap%d: dm=0x%x md=0x%x flags=0x%x\n",
					i,tap->tapdm_queue,tap->tapmd_queue,
					tap->tap_flags);
#endif
		break;
	default:
		return(EIO);
	}
	return(0);	/* return success */
}
#endif TAPVD

/* --- MODULE PART --- */

static int tapopen(q, dev, flag, sflag)
	queue_t *q;
	dev_t   dev;
	int    	flag;
	int	sflag;
{
	register int i;
	register struct tap *tap;

	if(!(q->q_ptr)){
		/*
		 * find first fit free slot
		 */
		for(i=0,tap=tap_tap;i<tap_cnt;i++,tap++){
			if(!(tap->tapdm_queue)){
				WR(q)->q_ptr = (char *) tap;
				q->q_ptr = (char *) tap; /* mark as open */
				tap->tapdm_queue = q;	
				return(0);
			}
		}
		return(OPENFAIL);
	}
	return(0);	
}

static int tapwput(q, mp)
	queue_t    *q;    
	mblk_t    *mp;   
{
	mblk_t    *bp;   	
	struct tap *tap;
	
	tap = (struct tap *)q->q_ptr;
	
	if((!(tap->tap_flags&TAP_REVERSE))&&tap->tapmd_queue){		
		if(mp->b_datap->db_type==M_DATA){
			if((bp=dupmsg(mp))!=NULL){	
				putnext(tap->tapmd_queue,bp);
			}
		}
	}
	putnext(q,mp);
}
	
static int taprput(q, mp)
	queue_t    *q;    
	mblk_t    *mp;   
{
	mblk_t    *bp;   	
	struct tap *tap;
	
	tap = (struct tap *)q->q_ptr;
	
	if((tap->tap_flags&TAP_REVERSE)&&tap->tapmd_queue){		
		if(mp->b_datap->db_type==M_DATA){
			if((bp=dupmsg(mp))!=NULL){	
				putnext(tap->tapmd_queue,bp);
			}
		}
	}
	putnext(q, mp);
}

static int tapclose(q, flag)
	queue_t    *q;
	int    flag;
{
	struct tap *tap;

	tap = (struct tap *)q->q_ptr;
	/* here i want to send a HANGUP */
	tap->tapdm_queue = NULL;
}

/* --- DRIVER PART --- */

static int tapcopen(q, dev, flag, sflag)
	queue_t *q;
	dev_t   dev;
	int    	flag;
	int	sflag;
{
	struct tap *tap;

#ifdef TAPCLONE
	/*
	 * if CLONEOPEN, pick first unconnected module.
	 * otherwise, check the minor device range.
	 */
	printf("tapopen: q=0x%x dev=%d flag=%d  sflag=%d\n",q,dev,flag,sflag);
	if(sflag==CLONEOPEN) {
		for(dev=0;dev<tap_cnt;dev++){
			if((tap_tap[dev].tapmd_queue == NULL) &&
			   (tap_tap[dev].tapdm_queue != NULL)){
				printf("tapopen: CLONE=%d\n",dev);
				break;
			}
		}
	} else {
		dev = minor(dev);
	}
#else
	/*
	 * check if non-driver open 
	 */
	if(sflag)
		return(OPENFAIL);
	dev = minor(dev);
#endif

	if(dev>= tap_cnt)
		return(OPENFAIL);
	if(q->q_ptr){
		u.u_error = EBUSY;	/* only 1 user of tapc at a time ??? */
		return(OPENFAIL);
	}

	tap = &tap_tap[dev];
	if(!(tap->tapdm_queue)){
		u.u_error = ENETUNREACH;	
		return(OPENFAIL);
	}

	/*
	 * if opened with O_NDELAY reverse the connection
	 */
	if(flag&FNDELAY){
		if(!suser()){
			u.u_error = EACCES;
			return(OPENFAIL);
		}
		tap->tap_flags |= TAP_REVERSE;
	} else
		tap->tap_flags &= ~TAP_REVERSE;

	WR(q)->q_ptr = (char *)tap;
	q->q_ptr = (char *)tap;
	tap->tapmd_queue = q;
	return(dev);	
}

static int tapcwput(q, mp)
	queue_t    *q;    
	mblk_t    *mp;   
{
	switch(mp->b_datap->db_type){
	case M_IOCTL: {			/* NAK all ioctl's */
		/* struct iocblk *iocp; */

		/* iocp = (struct iocblk *)mp->b_rptr; */
		mp->b_datap->db_type=M_IOCNAK;
		qreply(q,mp);
		break;
	}
	case M_FLUSH:
		if(*mp->b_rptr & FLUSHW)
			flushq(q,0);
		if(*mp->b_rptr & FLUSHR){
			flushq(RD(q),0);
			*mp->b_rptr &= ~FLUSHW;
			qreply(q,mp);
		} else
			freemsg(mp);
		break;
	case M_DATA: {
		struct tap *tap;
		
		tap = (struct tap *)q->q_ptr;	
		if(tap->tapdm_queue) {
			if(tap->tap_flags&TAP_REVERSE)
				putnext(WR(tap->tapdm_queue), mp);	
			else
				putnext(tap->tapdm_queue, mp);	
		} else {
			(void)putctl1(RD(q)->q_next, M_ERROR, ECONNRESET); 
			freemsg(mp);
		}
		break;
	}
		
	default:		/* discard other messages */
		freemsg(mp);
	}
}

static int tapcrput(q, mp)
	queue_t    *q;    
	mblk_t    *mp;   
{
	putnext(q, mp);		
}

static int tapcclose(q, flag)
	queue_t    *q;
	int    flag;
{
	struct tap *tap;

	tap = (struct tap *) q->q_ptr;
	tap->tapmd_queue = NULL;
}

#endif  NTAP
