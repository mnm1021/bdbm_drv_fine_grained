/**
 * Author: Yongseok Jin
 * File: devices/ocssd/dm_ocssd.h
 *
 * Description: Interfaces to access Open-Channel SSD for BlueDBM.
 */

#ifndef _BLUEDBM_DEV_OCSSD_H
#define _BLUEDBM_DEV_OCSSD_H

#include "bdbm_drv.h"
#include "params.h"

uint32_t dm_ocssd_probe (bdbm_drv_info_t* bdi, bdbm_device_params_t* param);
uint32_t dm_ocssd_open (bdbm_drv_info_t* bdi);
void dm_ocssd_close (bdbm_drv_info_t* bdi);
uint32_t dm_ocssd_make_req (bdbm_drv_info_t* bdi, bdbm_llm_req_t* ptr_llm_req);
uint32_t dm_ocssd_make_reqs (bdbm_drv_info_t* bdi, bdbm_hlm_req_t* ptr_hlm_req);
void dm_ocssd_end_req (bdbm_drv_info_t* bdi, bdbm_llm_req_t* ptr_llm_req);

uint32_t dm_ocssd_load (bdbm_drv_info_t* bdi, const char* fn);
uint32_t dm_ocssd_store (bdbm_drv_info_t* bdi, const char* fn);

#endif
