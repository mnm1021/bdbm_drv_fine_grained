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
#include <linux/mempool.h>

//for debug purpose
#include <linux/delay.h>

#include <linux/nvme.h>
#include <linux/lightnvm.h>
#include <linux/miscdevice.h>
#include <linux/moduleparam.h>
#include <linux/sem.h>
#include <uapi/linux/lightnvm.h>
#include <uapi/linux/nvme_ioctl.h>

#else
#error Invalid Platform (KERNEL_MODE)
#endif

#include "debug.h"
#include "dm_ocssd.h"
#include "dev_params.h"
#include "dev_ocssd.h"

extern struct list_head nvm_devices;
extern struct rw_semaphore nvm_lock;

static struct kmem_cache *general_rq_cache, *write_rq_cache;
static int init_global_caches (void);
static void free_global_caches (void);

/* interface for dm */
bdbm_dm_inf_t _bdbm_dm_inf = {
	.ptr_private = NULL,
	.probe = dm_ocssd_probe,
	.open = dm_ocssd_open,
	.close = dm_ocssd_close,
	.make_req = dm_ocssd_make_req,
	.make_reqs = NULL, 
	.end_req = dm_ocssd_end_req,
	.load = NULL, 
	.store = NULL,
};

extern bdbm_drv_info_t* _bdi_dm;

/***********************************
 * functions for device management *
 ***********************************/

/**
 * finds /dev/nvme0n1 from devices.
 * returns NULL if there is not.
 */
static struct nvm_dev* nvm_find_nvm_dev (const char* name)
{
	struct nvm_dev* dev;

	list_for_each_entry (dev, &nvm_devices, devices)
		if (!strcmp (name, dev->name))
			return dev;

	return NULL;
}

/**
 * Finds the NVMe Device from kernel.
 * tip) 'params' does not really work for this function,
 *       since device specification is fixed for CNEX-8800.
 *
 * @param bdi (bdbm_drv_info_t*): 			device information
 * @param params (bdbm_device_params_t*): 	given parameters
 * @return: 								0 if successful, else if not.
 */
uint32_t dm_ocssd_probe (bdbm_drv_info_t* bdi, bdbm_device_params_t* params)
{
	struct nvm_dev* dev;
	struct nvm_tgt_dev* tgt_dev;
	bdbm_ocssd_t* ocssd_drv;
	char* name = "nvme0n1";

	*params = get_default_device_params ();
	bdi->parm_dev = *params;

	down_write (&nvm_lock);
	dev = nvm_find_nvm_dev (name);
	up_write (&nvm_lock);

	if (!dev)
	{
		pr_err ("[dm_ocssd_probe] NVMe device not found\n");
		return -EINVAL;
	}

	init_global_caches ();

	/* initialize ocssd_drv */
	ocssd_drv = kzalloc (sizeof(bdbm_ocssd_t), GFP_KERNEL);

	tgt_dev = nvm_create_tgt_dev (dev, 0, 127);
	ocssd_drv->tgt_dev = tgt_dev;

	ocssd_drv->read_rq_pool = mempool_create_slab_pool (
			128, general_rq_cache);
	ocssd_drv->write_rq_pool = mempool_create_slab_pool (
			128, write_rq_cache);
	ocssd_drv->erase_rq_pool = mempool_create_slab_pool (
			128, general_rq_cache);

	bdi->ptr_dm_inf->ptr_private = (void*)ocssd_drv;

	bdbm_msg ("[dm_ocssd_probe] probe done!");

	return 0;
	
}

/**
 * initializes given NVMe Device. (nothing to do on this function)
 *
 * @param bdi (bdbm_drv_info_t*): 	device information
 * @return: 						0 if successful, else if not.
 */
uint32_t dm_ocssd_open (bdbm_drv_info_t* bdi)
{
	return 0;
}

/**
 * Close the target device of NVMe.
 *
 * @param bdi (bdbm_drv_info_t*): 	device information
 */
void dm_ocssd_close (bdbm_drv_info_t* bdi)
{
	bdbm_ocssd_t* ocssd_drv = (bdbm_ocssd_t*)bdi->ptr_dm_inf->ptr_private;
	struct nvm_tgt_dev* tgt_dev = ocssd_drv->tgt_dev;

	nvm_remove_tgt_dev (tgt_dev);

	mempool_destroy (ocssd_drv->read_rq_pool);
	mempool_destroy (ocssd_drv->write_rq_pool);
	mempool_destroy (ocssd_drv->erase_rq_pool);

	free_global_caches ();

	kfree (ocssd_drv);
}

/**
 * Creates and sends request for given low-level request.
 *
 * @param bdi (bdbm_drv_info_t*): 			device information
 * @param ptr_llm_req (bdbm_llm_req_t*): 	low-level request
 * @return: 								0 if successful, else if not.
 */
uint32_t dm_ocssd_make_req (bdbm_drv_info_t* bdi, bdbm_llm_req_t* ptr_llm_req)
{
	bdbm_ocssd_t* ocssd_drv = (bdbm_ocssd_t*)_bdi_dm->ptr_dm_inf->ptr_private;

	return dev_ocssd_make_req (ocssd_drv, ptr_llm_req);
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

/**
 * initializes global caches for requests.
 */
static int init_global_caches (void)
{
	general_rq_cache = kmem_cache_create("bdbm_g_rq",
			sizeof(struct nvm_rq) + 16, 0, 0, NULL);
	write_rq_cache = kmem_cache_create("bdbm_w_rq", 
			sizeof(struct nvm_rq) + 32, 0, 0, NULL);

	return 0;
}

/**
 * frees global caches.
 */
static void free_global_caches (void)
{
	kmem_cache_destroy (general_rq_cache);
	kmem_cache_destroy (write_rq_cache);
}














