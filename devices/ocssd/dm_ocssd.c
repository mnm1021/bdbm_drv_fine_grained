/**
 * Author: Yongseok Jin
 * File: devices/ocssd/dm_ocssd.c
 *
 * Description: Interfaces to access Open-Channel SSD for BlueDBM.
 */

#if defined (KERNEL_MODE)
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/sched/sysctl.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/blk-mq.h>

#include <linux/nvme.h>
#include <linux/lightnvm.h>
#include <uapi/linux/lightnvm.h>

#else
#error Invalid Platform (KERNEL_MODE)
#endif

#include "debug.h"
#include "dm_ocssd.h"
#include "dev_params.h"

#define NVME_QID_ANY -1

/* interface for dm */
bdbm_dm_inf_t _bdbm_dm_inf = {
	.ptr_private = NULL,
	.probe = dm_ocssd_probe,
	.open = dm_ocssd_open,
	.close = dm_ocssd_close,
	.make_req = dm_ocssd_make_req,
	.make_reqs = dm_ocssd_make_reqs,
	.end_req = dm_ocssd_end_req,
	.load = dm_ocssd_load,
	.store = dm_ocssd_store,
};

extern bdbm_drv_info_t* _bdi_dm;

/* NVMe device command */
typedef struct {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	nsid;
	__u64	rsvd2;
	__le64	metadata;
	__le64	prp1;
	__le64	prp2;
	__le64	spba;
	__le16	length;
	__le16	control;
	__le32	dsmgmt;
	__le64	slba;
} bdbm_nvme_command;

/* structs required for conversion */
struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct nvm_dev *ndev;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 nguid[16];
	uuid_t uuid;

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	u16 sgs;
	u32 sws;
	bool ext;
	u8 pi_type;
	unsigned long flags;
#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1
	u16 noiob;
};
struct nvme_request {
	struct nvme_command	*cmd;
	union nvme_result	result;
	u8			retries;
	u8			flags;
	u16			status;
};

static inline struct nvme_request *nvme_req(struct request *req)
{
	return blk_mq_rq_to_pdu(req);
}

/**
 * convert BlueDBM's low-level request into NVMe command.
 *
 * @param req (bdbm_llm_req_t *):	low-level request.
 * @param dev (struct nvm_dev *):	target device.
 * @param cmd (bdbm_nvme_cmd *):	(output) NVMe command.
 */
static void dm_nvm_rqtocmd (bdbm_llm_req_t* req,
		struct nvm_dev* dev,
		bdbm_nvme_command* cmd)
{
	int flags = 0;
	struct nvme_ns *ns = (struct nvme_ns *)(dev->q->queuedata);
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr ppa;
	dma_addr_t dma_meta_list;
	bdbm_phyaddr_t phyaddr = req->phyaddr;

	/* set physical address */
	ppa.ppa = ((u64)phyaddr.block_no) << geo->ppaf.blk_offset;
	ppa.ppa |= ((u64)phyaddr.page_no) << geo->ppaf.pg_offset;
	ppa.ppa |= ((u64)0) << geo->ppaf.sect_offset;
	ppa.ppa |= ((u64)phyaddr.chip_no) << geo->ppaf.pln_offset;
	ppa.ppa |= ((u64)phyaddr.punit_id) << geo->ppaf.lun_offset;
	ppa.ppa |= ((u64)phyaddr.channel_no) << geo->ppaf.ch_offset;

	/* set dma_meta_list */
	dev->ops->dev_dma_alloc(dev, dev->dma_pool, GFP_KERNEL, &dma_meta_list);

	/* TODO figure out GC R/W has any flags */
	switch(req->req_type)
	{
		/* write operation */
		case REQTYPE_WRITE:
		case REQTYPE_GC_WRITE:
		case REQTYPE_RMW_WRITE:
		case REQTYPE_META_WRITE:
			cmd->opcode = NVM_OP_PWRITE;
			flags = dev->geo.plane_mode >> 1;
			flags |= NVM_IO_SCRAMBLE_ENABLE;
			break;

		/* read operation */
		case REQTYPE_READ:
		case REQTYPE_GC_READ:
		case REQTYPE_RMW_READ:
		case REQTYPE_META_READ:
		case REQTYPE_READ_DUMMY:
			cmd->opcode = NVM_OP_PREAD;
			flags = NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE;
			break;

		/* erase operation for gc */
		case REQTYPE_GC_ERASE:
			cmd->opcode = NVM_OP_ERASE;
			flags = dev->geo.plane_mode >> 1;
			break;

		/* undefined request type */
		default:
			return;
	}

	cmd->nsid = cpu_to_le32(ns->ns_id);
	cmd->spba = cpu_to_le64(ppa.ppa);
	cmd->metadata = cpu_to_le64(dma_meta_list);
	cmd->control = cpu_to_le16(flags);
	cmd->length = cpu_to_le16(3); /* nr_ppas-1 : low level request is 16K, sector is 4K */
}

/**
 * NVMe request allocation.
 * this code is from {KERNEL_ROOT}/drivers/nvme/host/core.c.
 */
static struct request* dm_nvme_alloc_request(struct request_queue *q,
		struct nvme_command *cmd,
		unsigned int flags,
		int qid)
{
	unsigned op = nvme_is_write(cmd) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN;
	struct request *req;

	if (qid == NVME_QID_ANY) {
		req = blk_mq_alloc_request(q, op, flags);
	} else {
		req = blk_mq_alloc_request_hctx(q, op, flags, qid ? qid - 1 : 0);
	}

	if (IS_ERR(req))
		return req;

	req->cmd_flags |= REQ_FAILFAST_DRIVER;
	nvme_req(req)->cmd = cmd;

	return req;
}

/**
 * callback function for I/O.
 */
static void dm_nvm_end_io (struct request *rq, blk_status_t status)
{
	bdbm_llm_req_t* req = rq->end_io_data;
	
	_bdbm_dm_inf.end_req(_bdi_dm, req);

	kfree(nvme_req(rq)->cmd);
	blk_mq_free_request(rq);
}

/**
 * submit low-level I/O request to target device.
 *
 * @param dev (struct nvm_dev *):	target device.
 * @param req (bdbm_llm_req_t *):	low-level request.
 */
static uint32_t dm_nvm_submit_io (struct nvm_dev* dev, bdbm_llm_req_t* req)
{
	struct request_queue* q = dev->q;
	struct request* rq;
	struct bio* req_bio;
	bdbm_hlm_req_t* hlm_req;
	bdbm_blkio_req_t* blkio_req;
	bdbm_nvme_command* cmd;

	/* create NVMe command */
	cmd = kzalloc(sizeof(bdbm_nvme_command), GFP_KERNEL);
	if(!cmd)
		return -ENOMEM;
	dm_nvm_rqtocmd(req, q->queuedata, cmd);

	/* request initialization */
	rq = dm_nvme_alloc_request(q, (struct nvme_command *)cmd, 0, NVME_QID_ANY);
	if(IS_ERR(rq))
		return -1;

	rq->cmd_flags &= ~REQ_FAILFAST_DRIVER;

	hlm_req = (bdbm_hlm_req_t *)(req->ptr_hlm_req);
	blkio_req = (bdbm_blkio_req_t *)(hlm_req->blkio_req);
	req_bio = (struct bio *)(blkio_req->bio);
	if(req_bio) {
		blk_init_request_from_bio(rq, req_bio);
	}
	else {
		rq->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
		rq->__data_len = 0;
	}

	/* submit I/O with data for callback */
	rq->end_io_data = req;
	blk_execute_rq_nowait(q, NULL, rq, 0, dm_nvm_end_io);

	return 0;
}

/* device management functions */

/**
 * Initializes and finds the NVMe Device from kernel.
 * 'params' does not really care for this function,
 * since device specification is fixed for CNEX-8800.
 *
 * @param bdi (bdbm_drv_info_t *): 			device information
 * @param params (bdbm_device_params_t *): 	given parameters
 * @return: 								0 if successful, else if not.
 */
uint32_t dm_ocssd_probe (bdbm_drv_info_t* bdi, bdbm_device_params_t* params)
{
	/* TODO find NVMe Device. */
	return -1;
}

/**
 * TODO don't know what would come here, maybe probe can do it all.
 * Creates target block device from given NVMe Device.
 *
 * @param bdi (bdbm_drv_info_t *): 	device information
 * @return: 						0 if successful, else if not.
 */
uint32_t dm_ocssd_open (bdbm_drv_info_t* bdi)
{
	/* TODO initialize NVMe target device. */
	return -1;
}

/**
 * Close the target device of NVMe.
 *
 * @param bdi (bdbm_drv_info_t *): 	device information
 * @return: 						0 if successful, else if not.
 */
void dm_ocssd_close (bdbm_drv_info_t* bdi)
{
	/* TODO close target device. */
}

/**
 * Creates and sends request for given low-level request.
 *
 * @param bdi (bdbm_drv_info_t *): 			device information
 * @param ptr_llm_req (bdbm_llm_req_t *): 	low-level request
 * @return: 								0 if successful, else if not.
 */
uint32_t dm_ocssd_make_req (bdbm_drv_info_t* bdi, bdbm_llm_req_t* ptr_llm_req)
{
	struct nvm_dev* dev = NULL; /* TODO get nvm_dev from bdi */
	return dm_nvm_submit_io(dev, ptr_llm_req);
}

/**
 * Creates and sends request for given high-level request.
 *
 * @param bdi (bdbm_drv_info_t *): 	device information
 * @param hr (bdbm_llm_req_t *): 	high-level request
 * @return: 						0 if successful, else if not.
 */
uint32_t dm_ocssd_make_reqs (bdbm_drv_info_t* bdi, bdbm_hlm_req_t* hr)
{
#include "../../ftl/hlm_reqs_pool.h"

	uint32_t i, ret = 1;
	bdbm_llm_req_t* lr = NULL;
	struct nvm_dev* dev = NULL; /* TODO get nvm_dev from bdi */

	bdbm_hlm_for_each_llm_req (lr, hr, i) {
		if ((ret = dm_nvm_submit_io (dev, lr)) != 0) {
			bdbm_error ("nvm_submit_io failed");
			break;
		}
	}

	return ret;
}

/**
 * Callback function for the end of I/O request.
 *
 * @param bdi (bdbm_drv_info_t *):			device information
 * @param ptr_llm_req (bdbm_llm_req_t *): 	low-level request
 */
void dm_ocssd_end_req (bdbm_drv_info_t* bdi, bdbm_llm_req_t* ptr_llm_req)
{
	bdbm_bug_on (ptr_llm_req == NULL);
	bdi->ptr_llm_inf->end_req (bdi, ptr_llm_req);
}

/* OCSSD would not support snapshots. */

uint32_t dm_ocssd_load (bdbm_drv_info_t* bdi, const char* fn)
{
	return -1;
}

uint32_t dm_ocssd_store (bdbm_drv_info_t* bdi, const char* fn)
{
	return -1;
}













