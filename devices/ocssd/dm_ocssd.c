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
 *
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
 * 
 */
static inline struct ppa_addr create_blk_addr (uint64_t block_no,
		uint64_t punit_id, uint64_t channel_no, uint64_t plane_no)
{
	struct ppa_addr p;

	p.ppa = 0;
	p.g.blk = block_no;
	p.g.lun = punit_id / 16;
	p.g.ch = channel_no % 16;
	p.g.pl = plane_no;
	p.g.pg = 0;
	p.g.sec = 0;

	return p;
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
	char* name = "nvme0n1";

	*params = get_default_device_params ();
	bdi->parm_dev = *params;

	display_device_params (params);	

	down_write (&nvm_lock);
	dev = nvm_find_nvm_dev (name);
	up_write (&nvm_lock);

	if (!dev)
	{
		pr_err ("[dm_ocssd_probe] NVMe device not found\n");
		return -EINVAL;
	}

	bdi->ptr_dm_inf->ptr_private = (void*)dev;

	bdbm_msg ("[dm_ocssd_probe] probe done!");

	return 0;
	
}

/**
 * initializes given NVMe Device.
 *
 * @param bdi (bdbm_drv_info_t*): 	device information
 * @return: 						0 if successful, else if not.
 */
uint32_t dm_ocssd_open (bdbm_drv_info_t* bdi)
{
//	struct nvm_dev* dev;
//	bdbm_llm_req_t e_req;
//	int block_no, punit_id;
//
//	dev = (struct nvm_dev*)bdi->ptr_dm_inf->ptr_private;
//
//	memset (&e_req, 0x00, sizeof (bdbm_llm_req_t));
//	e_req.req_type = REQTYPE_GC_ERASE;
//
//	/* erase blocks. */
//	for (punit_id = 0; punit_id < 128; ++punit_id)
//	{
//		e_req.phyaddr.punit_id = punit_id / 16;
//		e_req.phyaddr.channel_no = punit_id % 16;
//		pr_info ("bdbm: erasing blocks.... (%d/127)\n", punit_id);
//
//		for (block_no = 0; block_no < 32; ++block_no)
//		{
//			e_req.phyaddr.block_no = block_no;
//			dev_ocssd_submit_vio (dev, &e_req);
//		}
//	}
	pr_info ("bdbm: erasing blocks.... done! OCSSD is initialized.\n");
	
	return 0;
}

/**
 * Close the target device of NVMe.
 *
 * @param bdi (bdbm_drv_info_t*): 	device information
 */
void dm_ocssd_close (bdbm_drv_info_t* bdi)
{
	return;
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
	struct nvm_dev* dev;
	int ret = -1;

	if (bdi == NULL)
	{
		pr_err ("[dm_ocssd_make_req] bdi is NULL\n");
		return -1;
	}

	dev = (struct nvm_dev*)bdi->ptr_dm_inf->ptr_private;
	if (dev == NULL)
	{
		pr_err ("[dm_ocssd_make_req] device information is NULL\n");
		return -1;
	}

	ret = dev_ocssd_submit_vio (dev, ptr_llm_req);

	dm_ocssd_end_req (bdi, ptr_llm_req);

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
	bdbm_bug_on (ptr_llm_req->ptr_qitem == NULL);
	bdi->ptr_llm_inf->end_req (bdi, ptr_llm_req);
}

