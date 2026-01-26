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

#ifndef SCENIC_IB_H
#define SCENIC_IB_H

#include <stdio.h>
#include <infiniband/verbs.h>
#include <infiniband/driver.h>
#include "cthread_bridge.h"
#include <x86intrin.h>
#include <smmintrin.h>
#include <immintrin.h>
#include <stddef.h> /* for size_t, offsetof */


/* struct vfpga_ucontext {
    // Underlying standard RDMA user context 
    struct ib_ucontext ibucontext;

    // Pointer to the vFPGA device associated with this user context
    struct list_head qp_list; 
    spinlock_t ctx_lock; 

    // FPGA virtualization hook 
    uint32_t hw_vmid; 
}; */ 

// Definition of the core struct that allows us to interact with the SCENIC and link to the standard ibv_context for RDMA verbs
struct scenic_ib_context {
    struct verbs_context ibv_ctx;

    // Custom fields for SCENIC IB -> Points of interaction as already done for the "original" Coyote cThread

    // Lock for thread safety 
    pthread_mutex_t scenic_lock;

    // List of all active QPs in this context
    struct list_head qp_list;

    // List of all active MRs in this context
    struct list_head mr_list;    

    // List of all active CQs in this context
    struct list_head cq_list;
}; 

// Helper Function to cast from ibv_context to scenic_ib_context
static inline struct scenic_ib_context *to_scenic_ib_context(struct ibv_context *ibctx) {
    struct verbs_context *vctx = container_of(ibctx, struct verbs_context, context);
    return container_of(vctx, struct scenic_ib_context, ibv_ctx);
}

// Definition of the core struct for a scenic_device 
struct scenic_ib_device {
  struct verbs_device verbs_dev; 
  int driver_abi_ver; 
}; 

// Helper Function to cast from ibv_device to a scenic_ib_device 
static inline struct scenic_ib_device *to_scenic_ib_device(struct ibv_device *ibvdev){
  return container_of(ibvdev, struct scenic_ib_device, verbs_dev.device);
}

// Structure to hold a protection domain 
struct scenic_ib_pd {
    struct ibv_pd ibv_pd; 
    uint32_t pdn;  
};

// Helper to cast from ibv_pd to scenic_ib_pd
static inline struct scenic_ib_pd *to_scenic_ib_pd(struct ibv_pd *ibv_pd) {
    return container_of(ibv_pd, struct scenic_ib_pd, ibv_pd);
}

// Structure to hold a memory region
struct scenic_ib_mr {
    struct verbs_mr verbs_mr;

    // Linkage in the list of MRs
    struct list_node mr_list_node;

    // Metadata that we later might need... 
    uint64_t vaddr; 
    uint64_t length;
    uint32_t lkey;
    uint32_t rkey;
};

// Helper to cast from ibv_mr to scenic_ib_mr  
static inline struct scenic_ib_mr *to_scenic_ib_mr(struct ibv_mr *ibv_mr) {
    struct verbs_mr *verbs_mr = container_of(ibv_mr, struct verbs_mr, ibv_mr);
    return container_of(verbs_mr, struct scenic_ib_mr, verbs_mr);
}

// Structure to hold a Completion Queue
struct scenic_ib_cq {
    struct ibv_cq ibv_cq; 

    // Linkage in the list of CQs
    struct list_node cq_list_node;

    // List of associated QPs
    struct list_head qp_send_list;
    struct list_head qp_recv_list;

    // Store the CQ number
    uint32_t cqn;
};

// Helper to cast from ibv_cq to scenic_ib_cq
static inline struct scenic_ib_cq *to_scenic_ib_cq(struct ibv_cq *ibv_cq) {
    return container_of(ibv_cq, struct scenic_ib_cq, ibv_cq);
}   

// Structure to hold a Queue Pair
struct scenic_ib_qp {
    struct ibv_qp ibv_qp;
    struct list_node qp_list_node;
    uint32_t local_qpn;
    uint32_t remote_qpn;
    uint32_t port; 
    uint32_t remote_psn;
    uint32_t local_psn;  
    uint32_t remote_rkey; 
    uint32_t local_rkey; 
    uint32_t remote_ip; 

    // cThread as the Coyote-FPGA abstraction
    struct cthread_handle *cthread;
};

// Helper to cast from ibv_qp to scenic_ib_qp
static inline struct scenic_ib_qp *to_scenic_ib_qp(struct ibv_qp *ibv_qp) {
    return container_of(ibv_qp, struct scenic_ib_qp, ibv_qp);
}

#endif // SCENIC_IB_H

