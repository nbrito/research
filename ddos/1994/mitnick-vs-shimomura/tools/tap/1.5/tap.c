/*
 * tap streams-module/driver kernel-loadable-module
 *
 * this is a combination of a STREAMS-module and a STREAMS-driver.
 * it pass module downstream M_DATA message upstream to the driver.
 *
 * Simon Ney -- neural@cs.tu-berlin.de / simon@bbisun.uu.sub.org
 */

#include "tap.h"
#if    NTAP > 0
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/user.h>
#ifdef TAPVD
#include <sys/conf.h>
#include <sun/vddrv.h>
#endif TAPVD

#ifndef lint
static	char sccsid[] = "@(#)tap.c	1.5 3/19/92";
#endif
/* 
 * --- DRIVER --- 
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

#ifdef TAPVD /* so we can have a permanent link AND loadable version */
struct streamtab tapcvdinfo = { &crinit, &cwinit, NULL, NULL };
#else
struct streamtab tapcinfo = { &crinit, &cwinit, NULL, NULL };
#endif
/*
 * --- MODULE --- 
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

#ifdef TAPVD /* so we can have a permanent link AND loadable version */
struct streamtab tapvdinfo = { &rinit, &winit, NULL, NULL };
#else
struct streamtab tapinfo = { &rinit, &winit, NULL, NULL };
#endif

struct tap {
	queue_t *tap_queue;	/* set on driver open */
};

/*
 * /dev/tapc? minor device number assignment
 */

#define TAPDEV0	0	/* downstream module data */
#define TAPDEV1	1	/* upstream module data */
static struct tap  tap_tap[NTAP];	/* static for now */
static int tap_cnt = NTAP;

/* 
 * --- loadable module support --- 
 */

#ifdef TAPVD
static int tapisopen;	/* keep track of the pushed-module open/close count */

extern int nodev();

static struct cdevsw		tap_cdevsw = { 
	nodev, nodev, nodev, nodev, nodev, nodev, nodev, 0, 
	&tapcvdinfo, 0
};

static struct vdldrv tapvdldrv = {
	VDMAGIC_DRV, "tapc/tap", 0, 0, 0, 0, 0, 0, &tap_cdevsw, 0, 0	
};


/*
 * this is the loadable-STREAMS-module kernel-module-loader
 */
static	struct fmodsw *saved_fmp;

static struct fmodsw *loadfmodsw(name,str)
char *name;
struct streamtab *str;
{
	struct fmodsw *fmp;
	int i;
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
	int i;

	switch(function_code){
	case VDLOAD:
		vdp->vdd_vdtab = (struct vdlinkage *) &tapvdldrv;
		if(saved_fmp){
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
		break;
	case VDUNLOAD:
		if(tapisopen)
			return(EBUSY);
		for(i=0;i<tap_cnt;i++)
			if(tap_tap[i].tap_queue)
			return(EBUSY);
		if(saved_fmp)
			unloadfmodsw(saved_fmp);
		break;
	case VDSTAT:
		break;
	default:
		return(EIO);
	}
	return(0);	/* return success */
}
#endif TAPVD

/* --- MODULE --- */

static int tapopen(q, dev, flag, sflag)
	queue_t *q;
	dev_t   dev;
	int    	flag;
	int	sflag;
{
#ifdef TAPVD
	tapisopen++;
#endif TAPVD
	return(0);	/* return success */
}


static int tapwput(q, mp)
	queue_t    *q;    
	mblk_t    *mp;   
{
	mblk_t    *bp;   	
	queue_t    *uq = tap_tap[TAPDEV0].tap_queue;    
	
	if(uq){		/* dup if tapc is open */
		if(mp->b_datap->db_type==M_DATA){
			if((bp=dupmsg(mp))!=NULL){	/* duplicate message */
				putnext(uq,bp);
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
	queue_t    *uq = tap_tap[TAPDEV1].tap_queue;    
	
	if(uq){		/* dup if tapc is open */
		if(mp->b_datap->db_type==M_DATA){
			if((bp=dupmsg(mp))!=NULL){	/* duplicate message */
				putnext(uq,bp);
			}
		}
	}
	putnext(q, mp);
}

static int tapclose(q, flag)
	queue_t    *q;
	int    flag;
{
#ifdef TAPVD
	tapisopen--;
#endif TAPVD
}

/* --- DRIVER --- */
static int tapcopen(q, dev, flag, sflag)
	queue_t *q;
	dev_t   dev;
	int    	flag;
	int	sflag;
{
	struct tap *tap;

	if(sflag)	/* check if non-driver open */
		return(OPENFAIL);
	dev = minor(dev);
	if(dev>= tap_cnt)
		return(OPENFAIL);
	if(q->q_ptr){
		u.u_error = EBUSY;	/* only 1 user of tapc at a time */
		return(OPENFAIL);
	}
	tap = &tap_tap[dev];
	q->q_ptr = (char *)tap;
	tap->tap_queue = q;
	return(dev);	
}

static int tapcwput(q, mp)
	queue_t    *q;    
	mblk_t    *mp;   
{
	switch(mp->b_datap->db_type){
	case M_IOCTL: {		/* NAK all ioctl's */
		struct iocblk *iocp;

		iocp = (struct iocblk *)mp->b_rptr;
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
	default:		/* discard all messages */
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
	tap->tap_queue = NULL;
}

#endif  NTAP
