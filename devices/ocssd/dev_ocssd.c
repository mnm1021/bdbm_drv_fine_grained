/**
 * Author: Yongseok Jin
 * File: devices/ocssd/dev_ocssd.c
 *
 * Description: functions for I/O submission to Open-Channel SSD.
 */

#include <linux/lightnvm.h>
#include <linux/nvme.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include "bdbm_drv.h"
#include "debug.h"
#include "dm_ocssd.h"
#include "dev_ocssd.h"
#include "dev_ocssd_command.h"

#define NVME_QID_ANY -1
#define ADMIN_TIMEOUT 60 * HZ
#define NVME_REQ_CANCELLED 1 << 0

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
	u8 retries;
	u8 flags;
	u16 status;
};


static int nvme_nvm_submit_vio(struct nvme_ns *ns,
					struct nvm_user_vio *vio);

static inline struct nvme_request *nvme_req(struct request *req)
{
	return blk_mq_rq_to_pdu(req);
}

static inline struct ppa_addr nvm_addr_create (
		bdbm_phyaddr_t phyaddr, int plane, int sector)
{
	struct ppa_addr p;

	p.g.blk	= phyaddr.block_no;
	p.g.pg	= phyaddr.page_no;
	p.g.sec	= sector;
	p.g.pl	= plane;
	p.g.lun	= phyaddr.punit_id / 16;
	p.g.ch	= phyaddr.channel_no % 16;
	p.g.reserved = 0;

	return p;
}

static inline uint64_t nvm_addr_gen2dev (
		struct nvm_geo* geo, struct ppa_addr addr)
{
	uint64_t d_addr = 0;

	d_addr |= ((uint64_t)addr.g.ch) << geo->ppaf.ch_offset;
	d_addr |= ((uint64_t)addr.g.lun) << geo->ppaf.lun_offset;
	d_addr |= ((uint64_t)addr.g.pl) << geo->ppaf.pln_offset;
	d_addr |= ((uint64_t)addr.g.blk) << geo->ppaf.blk_offset;
	d_addr |= ((uint64_t)addr.g.pg) << geo->ppaf.pg_offset;
	d_addr |= ((uint64_t)addr.g.sec) << geo->ppaf.sect_offset;

	return d_addr;
}

/**
 *
 */
static struct nvm_user_vio* dev_ocssd_create_vio (
		struct nvm_dev* dev, bdbm_llm_req_t* req)
{
	struct nvm_user_vio* vio;
	struct ppa_addr p;
	uint64_t* ppa_list;
	int i;
	uint8_t* addr = NULL;
	int naddr;
	__u8 opcode;

	switch (req->req_type)
	{
		case REQTYPE_READ_DUMMY:
			return NULL;

		case REQTYPE_WRITE:
		case REQTYPE_GC_WRITE:
		case REQTYPE_RMW_WRITE:
		case REQTYPE_META_WRITE:
			/* write operation */
			addr = kmalloc (0x1000 * 16, GFP_KERNEL);
			for (i = 0; i < 16; ++i)
				memcpy (0x1000 * i + addr, req->fmain.kp_ptr[i], 0x1000);

			ppa_list = kmalloc (sizeof (uint64_t) * 32, GFP_KERNEL);
			for (i = 0; i < 16; ++i)
			{
				p = nvm_addr_create (req->phyaddr, i / 4, i % 4);
				ppa_list[i] = nvm_addr_gen2dev (&dev->geo, p);
			}
			naddr = 16;

			opcode = 0x91;
			break;

		case REQTYPE_READ:
		case REQTYPE_GC_READ:
		case REQTYPE_RMW_READ:
		case REQTYPE_META_READ:
			/* read operation */
			addr = kmalloc (0x1000 * 16, GFP_KERNEL);

			ppa_list = kmalloc (sizeof (uint64_t) * 32, GFP_KERNEL);
			for (i = 0; i < 16; ++i)
			{
				p = nvm_addr_create (req->phyaddr, i / 4, i % 4);
				ppa_list[i] = nvm_addr_gen2dev (&dev->geo, p);
			}
			naddr = 16;

			opcode = 0x92;
			break;

		case REQTYPE_GC_ERASE:
			/* erase operation */
			ppa_list = kmalloc (sizeof (uint64_t) * 32, GFP_KERNEL);
			for (i = 0; i < 4; ++i)
			{
				p = nvm_addr_create (req->phyaddr, i, 0);
				ppa_list[i] = nvm_addr_gen2dev (&dev->geo, p);
			}
			naddr = 4;

			opcode = 0x90;
			break;

 		default:
			bdbm_error ("invalid REQTYPE (%u)", req->req_type);
			bdbm_bug_on (1);
			return NULL;
	}

	vio = kzalloc (sizeof (struct nvm_user_vio), GFP_KERNEL);

	vio->opcode			= opcode;
	vio->control		= 0x2 | 0x200;	/* QUAD_PLANE | IO_SCRAMBLE */
	vio->nppas			= naddr - 1;	/* zero-indexing */
	vio->ppa_list		= (__u64)ppa_list;
	vio->addr			= (__u64)addr;
	vio->data_len		= addr != NULL ? 0x1000 * 16 : 0;
	vio->metadata		= 0;
	vio->metadata_len	= 0;

	return vio;
}

static void dev_ocssd_end_vio (struct nvm_user_vio* vio, bdbm_llm_req_t* req)
{
	uint8_t* addr = (uint8_t*)vio->addr;
	int i;

	if (vio->opcode == 0x92)
	{
		for (i = 0; i < 16; ++i)
			memcpy (req->fmain.kp_ptr[i], 0x1000 * i + addr, 0x1000);
	}

	if (addr)
		kfree (addr);
	kfree ((void*)vio->ppa_list);
	kfree (vio);
}

uint32_t dev_ocssd_submit_vio (struct nvm_dev* dev, bdbm_llm_req_t* req)
{
	struct nvme_ns* ns = dev->q->queuedata;
	struct nvm_user_vio* vio = dev_ocssd_create_vio (dev, req);
	int result = nvme_nvm_submit_vio (ns, vio);

	pr_info("bdbm: request %x end with result %x\n", vio->opcode, result);
	if(result)
	{
		/* TODO log */
	}

	dev_ocssd_end_vio (vio, req);

	return result;
}




/***********************
 * NVMe I/O submission *
 * TODO sync => async  *
 ***********************/

static struct request *nvme_alloc_request(struct request_queue *q,
		struct nvme_command *cmd, unsigned int flags, int qid)
{
	unsigned op = nvme_is_write(cmd) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN;
	struct request *req;

	if (qid == NVME_QID_ANY) {
		req = blk_mq_alloc_request(q, op, flags);
	} else {
		req = blk_mq_alloc_request_hctx(q, op, flags,
				qid ? qid - 1 : 0);
	}
	if (IS_ERR(req))
		return req;

	req->cmd_flags |= REQ_FAILFAST_DRIVER;
	nvme_req(req)->cmd = cmd;

	return req;
}

static int nvme_nvm_submit_user_cmd(struct request_queue *q,
				struct nvme_ns *ns,
				struct nvme_nvm_command *vcmd,
				void *buf, unsigned int bufflen,
				void *meta_buf, unsigned int meta_len,
				void *ppa_buf, unsigned int ppa_len,
				u32 *result, u64 *status, unsigned int timeout)
{
	bool write = nvme_is_write((struct nvme_command *)vcmd);
	struct nvm_dev *dev = ns->ndev;
	struct gendisk *disk = ns->disk;
	struct request *rq;
	struct bio *bio = NULL;
	__le64 *ppa_list = NULL;
	dma_addr_t ppa_dma;
	__le64 *metadata = NULL;
	dma_addr_t metadata_dma;
	DECLARE_COMPLETION_ONSTACK(wait);
	int ret = 0;

	rq = nvme_alloc_request(q, (struct nvme_command *)vcmd, 0,
			NVME_QID_ANY);
	if (IS_ERR(rq)) {
		ret = -ENOMEM;
		goto err_cmd;
	}

	rq->timeout = timeout ? timeout : ADMIN_TIMEOUT;

	if (ppa_buf && ppa_len) {
		ppa_list = dma_pool_alloc(dev->dma_pool, GFP_KERNEL, &ppa_dma);
		if (!ppa_list) {
			ret = -ENOMEM;
			goto err_rq;
		}
		memcpy (ppa_list, (void *)ppa_buf, sizeof(u64) * (ppa_len + 1));
		vcmd->ph_rw.spba = cpu_to_le64(ppa_dma);
	} else {
		vcmd->ph_rw.spba = cpu_to_le64(ppa_buf);
	}

	if (buf && bufflen) {
		ret = blk_rq_map_kern(q, rq, buf, bufflen, GFP_KERNEL);
		if (ret)
			goto err_ppa;
		bio = rq->bio;

		if (meta_buf && meta_len) {
			metadata = dma_pool_alloc(dev->dma_pool, GFP_KERNEL,
								&metadata_dma);
			if (!metadata) {
				ret = -ENOMEM;
				goto err_map;
			}

			if (write) {
				memcpy(metadata, meta_buf, meta_len);
			}
			vcmd->ph_rw.metadata = cpu_to_le64(metadata_dma);
		}

		bio->bi_disk = disk;
	}

	blk_execute_rq(q, NULL, rq, 0);

	if (nvme_req(rq)->flags & NVME_REQ_CANCELLED)
		ret = -EINTR;
	else if (nvme_req(rq)->status & 0x7ff)
		ret = -EIO;
	if (result)
		*result = nvme_req(rq)->status & 0x7ff;
	if (status)
		*status = le64_to_cpu(nvme_req(rq)->result.u64);

	if (metadata && !ret && !write) {
		memcpy(meta_buf, (void *)metadata, meta_len);
	}

	if (meta_buf && meta_len)
		dma_pool_free(dev->dma_pool, metadata, metadata_dma);
err_map:
err_ppa:
	if (ppa_buf && ppa_len)
		dma_pool_free(dev->dma_pool, ppa_list, ppa_dma);
err_rq:
	blk_mq_free_request(rq);
err_cmd:
	return ret;
}

static int nvme_nvm_submit_vio(struct nvme_ns *ns,
					struct nvm_user_vio *vio)
{
	struct nvme_nvm_command c;
	unsigned int length;
	int ret;

	if (vio->flags)
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.ph_rw.opcode = vio->opcode;
	c.ph_rw.nsid = cpu_to_le32(ns->ns_id);
	c.ph_rw.control = cpu_to_le16(vio->control);
	c.ph_rw.length = cpu_to_le16(vio->nppas);

	length = (vio->nppas + 1) << ns->lba_shift;

	ret = nvme_nvm_submit_user_cmd(ns->queue, ns, &c,
			(void *)(uintptr_t)vio->addr, length,
			(void *)(uintptr_t)vio->metadata,
							vio->metadata_len,
			(void *)(uintptr_t)vio->ppa_list, vio->nppas,
			&vio->result, &vio->status, 0);

	if (ret)
		return -EFAULT;

	return ret;
}


















