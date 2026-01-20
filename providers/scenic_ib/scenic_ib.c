/**
  * Copyright (c) 2026, Systems Group, ETH Zurich
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without modification,
  * are permitted provided that the following conditions are met:
  *
  * 1. Redistributions of source code must retain the above copyright notice,
  * this list of conditions and the following disclaimer.
  * 2. Redistributions in binary form must reproduce the above copyright notice,
  * this list of conditions and the following disclaimer in the documentation
  * and/or other materials provided with the distribution.
  * 3. Neither the name of the copyright holder nor the names of its contributors
  * may be used to endorse or promote products derived from this software
  * without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
  * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
  * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  */

#define _GNU_SOURCE
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <sched.h>
#include <sys/param.h>
#include <util/symver.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
// #include "driver.h"
#include "scenic_ib.h"
#include "coyote_rdma_abi.h"

// Stub operation for querying the device attributes 
// TO BE IMPLEMENTED LATER
static int scenic_ib_query_device_ex(struct ibv_context *ibv_ctx, const struct ibv_query_device_ex_input *input, struct ibv_device_attr_ex *device_attr, size_t attr_size) {
    // Need to call ibv_cmd_query_device_any to get standard attributes first
    struct ib_uverbs_ex_query_device_resp resp;
    size_t resp_size = sizeof(resp);
    int ret;

    ret = ibv_cmd_query_device_any(ibv_ctx, input, device_attr, attr_size, &resp, &resp_size);
    if(ret) {
        return ret;
    }
    return 0; 
}

// Operation that allows to query the kernel for port-related attributes 
static int scenic_ib_query_port(struct ibv_context *ibv_ctx,
                                 uint8_t port_num,
                                 struct ibv_port_attr *port_attr) {
    // Call the query_port function of the kernel driver 
    struct ibv_query_port cmd;
    return ibv_cmd_query_port(ibv_ctx, port_num, port_attr, &cmd, sizeof(cmd));
}

// Function to allocate a Protection Domain
static struct ibv_pd *scenic_ib_alloc_pd(struct ibv_context *ibv_ctx) {
    printf("SCENIC IB: scenic_ib_alloc_pd - Entered function\n");
    struct scenic_ib_pd *spd; 
    struct ibv_alloc_pd cmd;
    struct userspace_cyt_rdma_alloc_pd_resp resp;
    int ret; 

    // Allocate memory for the scenic_ib_pd structure
    spd = calloc(1, sizeof(*spd));
    if(!spd) {
        return NULL;
    }

    // Call the kernel to allocate the PD 
    ret = ibv_cmd_alloc_pd(ibv_ctx, &spd->ibv_pd, &cmd, sizeof(cmd), &resp.ibv_resp, sizeof(resp));
    printf("SCENIC IB: scenic_ib_alloc_pd - After ibv_cmd_alloc_pd, ret=%d\n", ret);
    if(ret) {
        free(spd);
        return NULL;
    }

    // Save the PD number from the response in the scenic_ib_pd structure
    spd->pdn = resp.pdn;

    // Return the pointer to the embedded ibv_pd structure 
    return &spd->ibv_pd;
}

// Function to deallocate a Protection Domain
static int scenic_ib_dealloc_pd(struct ibv_pd *ibv_pd) {
    int ret; 

    ret = ibv_cmd_dealloc_pd(ibv_pd);
    if(ret) {
        return ret;
    } 

    // Free the memory we allocated for the scenic_ib_pd structure
    free(to_scenic_ib_pd(ibv_pd));
    return 0;
}

// Operations table for the SCENIC IB provider
// Link scenic_ib stub implementations to the verbs interface 
static const struct verbs_context_ops scenic_ib_ctx_ops = {
    .query_device_ex = scenic_ib_query_device_ex,
    .query_port   = scenic_ib_query_port,
    .alloc_pd = scenic_ib_alloc_pd, 
    .dealloc_pd = scenic_ib_dealloc_pd,
    // Other operations to be added later 
};

// ALLOC CONTEXT Function 
// Called when libibverbs finds a device matching scenic_ib
static struct verbs_context *scenic_ib_alloc_context(struct ibv_device *ibv_dev, int cmd_fd, void *private_data) {
    // VERY LOUD PRINT STATEMENT FOR DEBUGGING PURPOSES
    // printf("SCENIC IB: scenic_ib_alloc_context - START %s\n", ibv_dev->name);
    
    // Infrastructure elements 
    struct scenic_ib_context *scenic_ctx;
    struct verbs_context *vctx;
    struct ibv_get_context cmd; 
    struct userspace_cyt_rdma_alloc_ucontext_resp resp;

    // Allocate memory for the scenic_ib_context structure
    scenic_ctx = NULL;
    scenic_ctx = verbs_init_and_alloc_context(ibv_dev, cmd_fd, scenic_ctx, ibv_ctx, RDMA_DRIVER_UNKNOWN); 
    if(!scenic_ctx) {
        return NULL; 
    }

    vctx = &scenic_ctx->ibv_ctx;

    // Prepare the command structure 
    memset(&cmd, 0, sizeof(cmd));
    memset(&resp, 0, sizeof(resp));

    cmd.response = (uintptr_t)&resp;

    // printf("SCENIC IB: scenic_ib_alloc_context - AFTER verbs_init_and_alloc_context\n");

    // printf("SCENIC IB: scenic_ib_alloc_context - Calling ibv_cmd_get_context\n");

    if(ibv_cmd_get_context(&scenic_ctx->ibv_ctx, &cmd, sizeof(cmd), NULL, &resp.ibv_resp, sizeof(resp))) {
        // Failed to get context information from the kernel driver
        goto err_free; 
    }

    // printf("SCENIC IB: scenic_ib_alloc_context - AFTER ibv_cmd_get_context\n");

    // Assign ops to the wrapper
    verbs_set_ops(&scenic_ctx->ibv_ctx, &scenic_ib_ctx_ops);

    return &scenic_ctx->ibv_ctx;
    
    err_free: 
    free(scenic_ctx);
    return NULL;
}

static struct verbs_device *scenic_ib_alloc_device(struct verbs_sysfs_dev *sysfs_dev)
{
    struct scenic_ib_device *dev; 
    dev = calloc(1, sizeof(*dev)); 

    if(!dev){
        return NULL; 
    }

    // dev->verbs_dev.ops = &scenic_ib_device_ops; 
    dev->verbs_dev.sysfs = sysfs_dev; 
    return &dev->verbs_dev; 
}

static void scenic_ib_uninit_device(struct verbs_device *verbs_device) {
    struct scenic_ib_device *dev = (struct scenic_ib_device *)verbs_device;
    free(dev); 
}

static const struct verbs_match_ent scenic_match_table[] = {
    { .kind = VERBS_MATCH_DRIVER_ID, .u.driver_id = "coyote_driver" },
    {
        .kind = VERBS_MATCH_PCI,
        .vendor = 0x10ee, // Your Vendor (e.g., Xilinx)
        .device = 0x903f, // Your Device ID
    },
    { .kind = VERBS_MATCH_SENTINEL },
};

static const struct verbs_device_ops scenic_ib_device_ops = {
    .name = "coyote_driver", 
    .match_min_abi_version = 0,
    .match_max_abi_version = INT_MAX,
    .alloc_context = scenic_ib_alloc_context,
    .alloc_device = scenic_ib_alloc_device,
    .uninit_device = scenic_ib_uninit_device,
    .match_table = scenic_match_table,
}; 

/* static void __attribute__((constructor)) scenic_ib_register_driver(void) {
    // "myfpga" must match the string returned by your Kernel Driver's IB_DEVICE_NAME
    printf("SCENIC IB: Registering scenic_ib driver\n");
    verbs_register_driver(&scenic_ib_device_ops);
} */ 

/* static const struct verbs_device_ops scenic_ib_device_ops = {
    .name = "scenic_ib",
    
    // Other device operations can be added here 
    .match_table = NULL, // No specific matching table for now
    .alloc_device = NULL, // Device allocation function can be added later
    .uninit_device = NULL, // Device uninitialization function can be added later
    .alloc_context = scenic_ib_alloc_context,
    .import_context = NULL // Import context function can be added later
}; */ 


static bool is_scenic_ib_dev(struct ibv_device *device) {
    struct verbs_device *verbs_device = verbs_get_device(device);
    return verbs_device->ops == &scenic_ib_device_ops;
}

PROVIDER_DRIVER(scenic_ib, scenic_ib_device_ops);