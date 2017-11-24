/**
 * Author: Yongseok Jin
 * File: devices/ocssd/dev_ocssd.h
 *
 * Description: functions for I/O submission to Open-Channel SSD.
 */

#ifndef _BLUEDBM_DEV_OCSSD_H
#define _BLUEDBM_DEV_OCSSD_H

#include "bdbm_drv.h"
#include "dm_ocssd.h"

#include <linux/bio.h>
#include <linux/lightnvm.h>

uint32_t dev_ocssd_submit_vio (struct nvm_dev* dev,
		bdbm_llm_req_t* req);

#endif
