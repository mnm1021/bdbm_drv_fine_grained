/**
 *
 */

#ifndef _BLUEDBM_DEV_OCSSD_H
#define _BLUEDBM_DEV_OCSSD_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/sem.h>
#include <linux/bitmap.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/lightnvm.h>
#include <linux/sched/sysctl.h>

#include "bdbm_drv.h"

typedef struct {
	struct nvm_tgt_dev* tgt_dev;
	mempool_t* read_rq_pool;
	mempool_t* write_rq_pool;
	mempool_t* erase_rq_pool;
} bdbm_ocssd_t;

/* I/O submit */
int dev_ocssd_make_req (bdbm_ocssd_t* ocssd_drv, bdbm_llm_req_t* req);

/* nvm_rq */
struct nvm_rq* dev_ocssd_alloc_rqd (bdbm_ocssd_t* ocssd_drv, int type);
void dev_ocssd_free_rqd (bdbm_ocssd_t* ocssd_drv, struct nvm_rq* rqd, int type);

/* nvm_tgt_dev */
struct nvm_tgt_dev *nvm_create_tgt_dev(struct nvm_dev *dev,
					      int lun_begin, int lun_end);
void nvm_remove_tgt_dev(struct nvm_tgt_dev *tgt_dev);

#endif
