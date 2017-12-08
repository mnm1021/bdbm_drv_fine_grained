/**
 *
 */

#include "dev_ocssd.h"
#include "dm_ocssd.h"
#include "bdbm_drv.h"

typedef struct {
	u64 reserved;
	__le64 lba;
} meta_struct;

typedef struct {
	bdbm_llm_req_t* llm_req;
	uint8_t* buf;
} dev_ocssd_private_t;

struct nvm_ch_map {
	int ch_off;
	int nr_luns;
	int *lun_offs;
};

struct nvm_dev_map {
	struct nvm_ch_map *chnls;
	int nr_chnls;
};

#define DMA_META_SIZE (64 * sizeof(meta_struct))

extern bdbm_drv_info_t* _bdi_dm;

/********************
 * inline functions *
 ********************/

/**
 * convert bdbm_phyaddr_t into ppa_addr.
 */
static inline struct ppa_addr convert_addr (bdbm_phyaddr_t phyaddr,
		uint16_t plane, uint16_t sector)
{
	struct ppa_addr p;

	p.g.ch = phyaddr.channel_no;
	p.g.lun = phyaddr.chip_no;
	p.g.blk = phyaddr.block_no;
	p.g.pg = phyaddr.page_no;

	p.g.pl = plane;
	p.g.sec = sector;

	p.g.reserved = 0;

	return p;
}

/*******************************
 * functions related to nvm_rq *
 *******************************/

static void dev_ocssd_end_io (struct nvm_rq* rqd);

struct nvm_rq* dev_ocssd_alloc_rqd (bdbm_ocssd_t* ocssd_drv, int type)
{
	mempool_t* pool;
	struct nvm_rq* rqd;
	int rq_size;

	switch (type)
	{
		case REQTYPE_READ:
		case REQTYPE_GC_READ:
		case REQTYPE_RMW_READ:
		case REQTYPE_META_READ:
			pool = ocssd_drv->read_rq_pool;
			rq_size = sizeof(struct nvm_rq) + 16;
			break;

		case REQTYPE_WRITE:
		case REQTYPE_GC_WRITE:
		case REQTYPE_RMW_WRITE:
		case REQTYPE_META_WRITE:
			pool = ocssd_drv->write_rq_pool;
			rq_size = sizeof(struct nvm_rq) + 32;
			break;

		case REQTYPE_GC_ERASE:
			pool = ocssd_drv->erase_rq_pool;
			rq_size = sizeof(struct nvm_rq) + 16;
			break;

		case REQTYPE_READ_DUMMY:
			return NULL;

		default:
			return NULL;
	}

	rqd = mempool_alloc (pool, GFP_KERNEL);
	memset (rqd, 0, rq_size);

	/* set callback */
	rqd->end_io = dev_ocssd_end_io;

	return rqd;
}

void dev_ocssd_free_rqd (bdbm_ocssd_t* ocssd_drv, struct nvm_rq* rqd, int type)
{
	struct nvm_tgt_dev* dev = ocssd_drv->tgt_dev;
	mempool_t* pool;

	switch (type)
	{
		case REQTYPE_READ:
		case REQTYPE_GC_READ:
		case REQTYPE_RMW_READ:
		case REQTYPE_META_READ:
			pool = ocssd_drv->read_rq_pool;
			break;

		case REQTYPE_WRITE:
		case REQTYPE_GC_WRITE:
		case REQTYPE_RMW_WRITE:
		case REQTYPE_META_WRITE:
			pool = ocssd_drv->write_rq_pool;
			break;

		case REQTYPE_GC_ERASE:
			pool = ocssd_drv->erase_rq_pool;
			break;

		default:
			return;
	}

	nvm_dev_dma_free (dev->parent, rqd->meta_list, rqd->dma_meta_list);
	mempool_free (rqd, pool);
}

/****************************
 * functions to handle I/Os *
 ****************************/

static void dev_ocssd_set_ppalist (struct nvm_rq* rqd)
{
	meta_struct* meta_list = rqd->meta_list;
	dev_ocssd_private_t* ocssd_priv;
	bdbm_phyaddr_t phyaddr;
	int64_t* lpas;
	int i;

	ocssd_priv = (dev_ocssd_private_t*)rqd->private;
	phyaddr = ocssd_priv->llm_req->phyaddr;
	lpas = ocssd_priv->llm_req->logaddr.lpa;

	if (rqd->opcode == NVM_OP_ERASE)
	{
		for (i = 0; i < rqd->nr_ppas; ++i)
		{
			rqd->ppa_list[i] = convert_addr (phyaddr, i, 0);
		}
	}
	else
	{
		for (i = 0; i < rqd->nr_ppas; ++i)
		{
			meta_list[i].lba = cpu_to_le64(lpas[i]);
			rqd->ppa_list[i] = convert_addr (phyaddr, i / 4, i % 4);
		}
	}
}

static int dev_ocssd_submit_io (struct nvm_tgt_dev* tgt_dev, struct nvm_rq* rqd)
{
	return nvm_submit_io (tgt_dev, rqd);
}

static int dev_ocssd_read (bdbm_ocssd_t* ocssd_drv, struct nvm_rq* rqd,
		bdbm_llm_req_t* llm_req)
{
	struct nvm_tgt_dev* dev = ocssd_drv->tgt_dev;
	struct bio* bio;
	dev_ocssd_private_t* ocssd_priv;
	int ret = NVM_IO_ERR;

	ocssd_priv = kmalloc (sizeof(dev_ocssd_private_t), GFP_KERNEL);
	ocssd_priv->llm_req = llm_req;
	ocssd_priv->buf = kzalloc (4096 * BDBM_MAX_PAGES, GFP_KERNEL);

	/* bio initialization */
	bio = bio_map_kern (dev->q, ocssd_priv->buf, 4096 * BDBM_MAX_PAGES, GFP_KERNEL);
	if (IS_ERR(bio))
	{
		pr_err ("bdbm: bio_map_kern has failed\n");
	}
	bio->bi_iter.bi_sector = 0;
	bio_set_op_attrs (bio, REQ_OP_READ, 0);

	/* setup rqd */
	rqd->opcode = NVM_OP_PREAD;
	rqd->nr_ppas = 16;
	rqd->flags = NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE | dev->geo.plane_mode >> 1;
	rqd->private = ocssd_priv;
	rqd->bio = bio;

	/* ppa, meta list initialization */
	rqd->meta_list = nvm_dev_dma_alloc (dev->parent, GFP_KERNEL,
							&rqd->dma_meta_list);
	
	rqd->ppa_list = rqd->meta_list + DMA_META_SIZE;
	rqd->dma_ppa_list =rqd->dma_meta_list + DMA_META_SIZE;

	dev_ocssd_set_ppalist (rqd);

	/* submit io */
	ret = dev_ocssd_submit_io (dev, rqd);

	if (ret)
	{
		bio_put (bio);
		return ret;
	}

	return NVM_IO_OK;
}

static int dev_ocssd_write (bdbm_ocssd_t* ocssd_drv, struct nvm_rq* rqd,
		bdbm_llm_req_t* llm_req)
{
	struct nvm_tgt_dev* dev = ocssd_drv->tgt_dev;
	struct bio* bio;
	struct nvm_rq* e_rqd;
	dev_ocssd_private_t* ocssd_priv;
	uint8_t** kp_ptr = llm_req->fmain.kp_ptr;
	int ret = NVM_IO_ERR;
	int i;

	/* erase first if page number is 0. */
	if (llm_req->phyaddr.page_no == 0)
	{
		/* erase request creation */
		e_rqd = mempool_alloc (ocssd_drv->erase_rq_pool, GFP_KERNEL);
		memset (e_rqd, 0, sizeof(struct nvm_rq) + 16);
		e_rqd->opcode = NVM_OP_ERASE;
		e_rqd->nr_ppas = 4;
		e_rqd->flags = dev->geo.plane_mode >> 1;
		e_rqd->bio = NULL;

		/* ppa, meta list initialization */
		e_rqd->meta_list = nvm_dev_dma_alloc (dev->parent, GFP_KERNEL,
								&e_rqd->dma_meta_list);
	
		e_rqd->ppa_list = e_rqd->meta_list + DMA_META_SIZE;
		e_rqd->dma_ppa_list =e_rqd->dma_meta_list + DMA_META_SIZE;

		e_rqd->ppa_list[0] = convert_addr (llm_req->phyaddr, 0, 0);
		e_rqd->ppa_list[1] = convert_addr (llm_req->phyaddr, 1, 0);
		e_rqd->ppa_list[2] = convert_addr (llm_req->phyaddr, 2, 0);
		e_rqd->ppa_list[3] = convert_addr (llm_req->phyaddr, 3, 0);

		/* submit e_rqd in synchronously */
		nvm_submit_io_sync (dev, e_rqd);
	
		/* free e_rqd */
		nvm_dev_dma_free (dev->parent, e_rqd->meta_list, e_rqd->dma_meta_list);
		mempool_free (e_rqd, ocssd_drv->erase_rq_pool);
	}

	ocssd_priv = kmalloc (sizeof(dev_ocssd_private_t), GFP_KERNEL);
	ocssd_priv->llm_req = llm_req;
	ocssd_priv->buf = kzalloc (4096 * BDBM_MAX_PAGES, GFP_KERNEL);

	/* copy data from fmain */
	for (i = 0; i < 16; ++i)
	{
		memcpy (ocssd_priv->buf + i*4096, kp_ptr[i], 4096);
	}

	/* bio initialization */
	bio = bio_map_kern (dev->q, ocssd_priv->buf, 4096 * BDBM_MAX_PAGES, GFP_KERNEL);
	if (IS_ERR(bio))
	{
		pr_err ("bdbm: bio_map_kern has failed\n");
	}
	bio->bi_iter.bi_sector = 0;
	bio_set_op_attrs (bio, REQ_OP_WRITE, 0);

	/* setup rqd */
	rqd->opcode = NVM_OP_PWRITE;
	rqd->nr_ppas = 16;
	rqd->flags = NVM_IO_SCRAMBLE_ENABLE | dev->geo.plane_mode >> 1;
	rqd->private = ocssd_priv;
	rqd->bio = bio;

	/* ppa, meta list initialization */
	rqd->meta_list = nvm_dev_dma_alloc (dev->parent, GFP_KERNEL,
							&rqd->dma_meta_list);
	
	rqd->ppa_list = rqd->meta_list + DMA_META_SIZE;
	rqd->dma_ppa_list =rqd->dma_meta_list + DMA_META_SIZE;

	dev_ocssd_set_ppalist (rqd);

	/* submit io */
	ret = dev_ocssd_submit_io (dev, rqd);

	if (ret)
	{
		bio_put (bio);
		return ret;
	}

	return NVM_IO_OK;
}

static int dev_ocssd_erase (bdbm_ocssd_t* ocssd_drv, struct nvm_rq* rqd,
		bdbm_llm_req_t* llm_req)
{
	struct nvm_tgt_dev* dev = ocssd_drv->tgt_dev;
	dev_ocssd_private_t* ocssd_priv;
	int ret = NVM_IO_ERR;

	ocssd_priv = kmalloc (sizeof(dev_ocssd_private_t), GFP_KERNEL);
	ocssd_priv->llm_req = llm_req;
	ocssd_priv->buf = NULL;

	rqd->opcode = NVM_OP_ERASE;
	rqd->nr_ppas = 4;
	rqd->flags = dev->geo.plane_mode >> 1;
	rqd->private = ocssd_priv;
	rqd->bio = NULL;

	/* ppa, meta list initialization */
	rqd->meta_list = nvm_dev_dma_alloc (dev->parent, GFP_KERNEL,
							&rqd->dma_meta_list);
	
	rqd->ppa_list = rqd->meta_list + DMA_META_SIZE;
	rqd->dma_ppa_list =rqd->dma_meta_list + DMA_META_SIZE;

	dev_ocssd_set_ppalist (rqd);

	/* submit io */
	ret = dev_ocssd_submit_io (dev, rqd);

	if (ret)
	{
		return ret;
	}

	return NVM_IO_OK;
}

int dev_ocssd_make_req (bdbm_ocssd_t* ocssd_drv, bdbm_llm_req_t* req)
{
	struct nvm_rq* rqd;
	int ret;

	switch (req->req_type)
	{
		case REQTYPE_READ:
		case REQTYPE_GC_READ:
		case REQTYPE_RMW_READ:
		case REQTYPE_META_READ:
			rqd = dev_ocssd_alloc_rqd (ocssd_drv, req->req_type);
			ret = dev_ocssd_read (ocssd_drv, rqd, req);
			break;

		case REQTYPE_WRITE:
		case REQTYPE_GC_WRITE:
		case REQTYPE_RMW_WRITE:
		case REQTYPE_META_WRITE:
			rqd = dev_ocssd_alloc_rqd (ocssd_drv, req->req_type);
			ret = dev_ocssd_write (ocssd_drv, rqd, req);
			break;

		case REQTYPE_GC_ERASE:
			rqd = dev_ocssd_alloc_rqd (ocssd_drv, req->req_type);
			ret = dev_ocssd_erase (ocssd_drv, rqd, req);
			break;

		case REQTYPE_READ_DUMMY:
			ret = -1;

		default:
			ret = -1;
	}

	return ret;
}

/**
 * I/O callback function.
 */
static void dev_ocssd_end_io (struct nvm_rq* rqd)
{
	int i;

	dev_ocssd_private_t* ocssd_priv = (dev_ocssd_private_t*)rqd->private;
	bdbm_llm_req_t* req = ocssd_priv->llm_req;
	bdbm_ocssd_t* ocssd_drv = (bdbm_ocssd_t*)_bdi_dm->ptr_dm_inf->ptr_private;

	if (rqd->opcode == NVM_OP_PREAD)
	{
		/* copy data to fmain */
		for (i = 0; i < 16; ++i)
		{
			if (req->fmain.kp_stt[i] == KP_STT_DATA)
			{
				memcpy (req->fmain.kp_ptr[i], ocssd_priv->buf + i*4096 ,4096);
			}
		}
	}

	req->ret = rqd->error;

	if (rqd->error)
	{
		pr_err ("bdbm: request %x returned %x error code.\n", rqd->opcode, rqd->error);
	}

	dev_ocssd_free_rqd (ocssd_drv, rqd, req->req_type);

	if (ocssd_priv->buf)
		kfree (ocssd_priv->buf);
	kfree (ocssd_priv);

	/* end_req */
	dm_ocssd_end_req (_bdi_dm, req);
}

/********************************
 * functions related to tgt_dev *
 ********************************/

/**
 * creates nvm_tgt_dev from device.
 * this code is from lightnvm driver.
 */
struct nvm_tgt_dev *nvm_create_tgt_dev(struct nvm_dev *dev,
					      int lun_begin, int lun_end)
{
	struct nvm_tgt_dev *tgt_dev = NULL;
	struct nvm_dev_map *dev_rmap = dev->rmap;
	struct nvm_dev_map *dev_map;
	struct ppa_addr *luns;
	int nr_luns = lun_end - lun_begin + 1;
	int luns_left = nr_luns;
	int nr_chnls = nr_luns / dev->geo.luns_per_chnl;
	int nr_chnls_mod = nr_luns % dev->geo.luns_per_chnl;
	int bch = lun_begin / dev->geo.luns_per_chnl;
	int blun = lun_begin % dev->geo.luns_per_chnl;
	int lunid = 0;
	int lun_balanced = 1;
	int prev_nr_luns;
	int i, j;

	nr_chnls = (nr_chnls_mod == 0) ? nr_chnls : nr_chnls + 1;

	dev_map = kmalloc(sizeof(struct nvm_dev_map), GFP_KERNEL);
	if (!dev_map)
		goto err_dev;

	dev_map->chnls = kcalloc(nr_chnls, sizeof(struct nvm_ch_map),
								GFP_KERNEL);
	if (!dev_map->chnls)
		goto err_chnls;

	luns = kcalloc(nr_luns, sizeof(struct ppa_addr), GFP_KERNEL);
	if (!luns)
		goto err_luns;

	prev_nr_luns = (luns_left > dev->geo.luns_per_chnl) ?
					dev->geo.luns_per_chnl : luns_left;
	for (i = 0; i < nr_chnls; i++) {
		struct nvm_ch_map *ch_rmap = &dev_rmap->chnls[i + bch];
		int *lun_roffs = ch_rmap->lun_offs;
		struct nvm_ch_map *ch_map = &dev_map->chnls[i];
		int *lun_offs;
		int luns_in_chnl = (luns_left > dev->geo.luns_per_chnl) ?
					dev->geo.luns_per_chnl : luns_left;

		if (lun_balanced && prev_nr_luns != luns_in_chnl)
			lun_balanced = 0;

		ch_map->ch_off = ch_rmap->ch_off = bch;
		ch_map->nr_luns = luns_in_chnl;

		lun_offs = kcalloc(luns_in_chnl, sizeof(int), GFP_KERNEL);
		if (!lun_offs)
			goto err_ch;

		for (j = 0; j < luns_in_chnl; j++) {
			luns[lunid].ppa = 0;
			luns[lunid].g.ch = i;
			luns[lunid++].g.lun = j;

			lun_offs[j] = blun;
			lun_roffs[j + blun] = blun;
		}

		ch_map->lun_offs = lun_offs;

		/* when starting a new channel, lun offset is reset */
		blun = 0;
		luns_left -= luns_in_chnl;
	}

	dev_map->nr_chnls = nr_chnls;

	tgt_dev = kmalloc(sizeof(struct nvm_tgt_dev), GFP_KERNEL);
	if (!tgt_dev)
		goto err_ch;

	memcpy(&tgt_dev->geo, &dev->geo, sizeof(struct nvm_geo));
	/* Target device only owns a portion of the physical device */
	tgt_dev->geo.nr_chnls = nr_chnls;
	tgt_dev->geo.nr_luns = nr_luns;
	tgt_dev->geo.luns_per_chnl = (lun_balanced) ? prev_nr_luns : -1;
	tgt_dev->total_secs = nr_luns * tgt_dev->geo.sec_per_lun;
	tgt_dev->q = dev->q;
	tgt_dev->map = dev_map;
	tgt_dev->luns = luns;
	memcpy(&tgt_dev->identity, &dev->identity, sizeof(struct nvm_id));

	tgt_dev->parent = dev;

	return tgt_dev;
err_ch:
	while (--i >= 0)
		kfree(dev_map->chnls[i].lun_offs);
	kfree(luns);
err_luns:
	kfree(dev_map->chnls);
err_chnls:
	kfree(dev_map);
err_dev:
	pr_err ("bdbm: create_tgt_dev failed.\n");
	return tgt_dev;
}

/**
 * releases tgt_dev.
 * this code is from lightnvm driver.
 */
void nvm_remove_tgt_dev(struct nvm_tgt_dev *tgt_dev)
{
	struct nvm_dev *dev = tgt_dev->parent;
	struct nvm_dev_map *dev_map = tgt_dev->map;
	int i, j;

	for (i = 0; i < dev_map->nr_chnls; i++) {
		struct nvm_ch_map *ch_map = &dev_map->chnls[i];
		int *lun_offs = ch_map->lun_offs;
		int ch = i + ch_map->ch_off;

		for (j = 0; j < ch_map->nr_luns; j++) {
			int lun = j + lun_offs[j];
			int lunid = (ch * dev->geo.luns_per_chnl) + lun;

			WARN_ON(!test_and_clear_bit(lunid,
						dev->lun_map));
		}

		kfree(ch_map->lun_offs);
	}

	kfree(dev_map->chnls);
	kfree(dev_map);

	kfree(tgt_dev->luns);
	kfree(tgt_dev);
}
