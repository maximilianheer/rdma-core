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
    // printf("SCENIC IB: scenic_ib_alloc_pd - Entered function\n");
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
    // printf("SCENIC IB: scenic_ib_alloc_pd - After ibv_cmd_alloc_pd, ret=%d\n", ret);
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

// Function to register a new memory region
static struct ibv_mr *scenic_reg_mr(struct ibv_pd *ibv_pd, void *addr, size_t length, uint64_t hca_va, int access) {
    printf("SCENIC IB: scenic_reg_mr - Entered function\n");
    // Check whether the provided addr is 64B-aligned 
    if(((uintptr_t)addr % 64) != 0) {
        errno = EINVAL;
        return NULL; 
    }

    // Step 1: Define all the necessary variables
    struct scenic_ib_context *scenic_ctx = to_scenic_ib_context(ibv_pd->context);
    struct scenic_ib_mr *mr; 
    struct ibv_reg_mr cmd;
    struct userspace_cyt_rdma_reg_mr_resp resp;
    int ret;

    // Step 2: Allocate memory for the scenic_ib_mr structure
    mr = calloc(1, sizeof(*mr));
    if(!mr) {
        printf("SCENIC IB: scenic_reg_mr - calloc failed\n");
        return NULL;
    }   

    // Step 3: Talk to the kernel to register the memory region 
    printf("SCENIC IB: scenic_reg_mr - Calling ibv_cmd_reg_mr\n");
    ret = ibv_cmd_reg_mr(ibv_pd, addr, length, (uintptr_t)addr, access, &mr->verbs_mr, &cmd, sizeof(cmd), &resp.ibv_resp, sizeof(resp));
    if(ret) {
        printf("SCENIC IB: scenic_reg_mr - ibv_cmd_reg_mr failed with ret=%d\n", ret);
        return NULL;
    }

    // Step 3: Populate the metadata fields in the scenic_ib_mr structure
    mr->vaddr = (uint64_t)(uintptr_t)addr;
    mr->length = (uint64_t)length;
    mr->lkey = resp.lkey; 
    mr->rkey = resp.rkey; 
    printf("SCENIC IB: scenic_reg_mr - Registered MR: vaddr=0x%lx, length=%lu, lkey=0x%x, rkey=0x%x\n", mr->vaddr, mr->length, mr->lkey, mr->rkey);

    // Step 4: Store the scenic_ib_mr structure in the local list of MRs
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    list_add_tail(&scenic_ctx->mr_list, &mr->mr_list_node);
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);
    printf("SCENIC IB: scenic_reg_mr - Added MR to mr_list\n");

    // Step 5: Mutual cross-check with all registered QPs / cthreads: Every QP must be aware of this MR
    // Iterate over all QPs and map this MR to their cthreads
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    struct scenic_ib_qp *qp;
    list_for_each(&scenic_ctx->qp_list, qp, qp_list_node) {
        if (qp->cthread) {
            int map_ret = cthread_user_map(qp->cthread, (void *)mr->vaddr, (uint32_t)mr->length);
            if (map_ret) {
                printf("SCENIC IB: scenic_reg_mr - cthread_user_map failed for QP %u with ret=%d\n", qp->local_qpn, map_ret);
            } else {
                printf("SCENIC IB: scenic_reg_mr - Mapped MR to QP %u cthread\n", qp->local_qpn);
            }
        }
    }
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);

    return &mr->verbs_mr.ibv_mr; 
}

// Function to deregister a memory region
static int scenic_dereg_mr(struct verbs_mr *vmr) {
    struct scenic_ib_mr *mr = to_scenic_ib_mr(&vmr->ibv_mr);
    struct scenic_ib_context *scenic_ctx = to_scenic_ib_context(vmr->ibv_mr.context);
    int ret;

    // Step 1: Remove the MR from the local list of MRs and unmap from all QPs
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    list_del(&mr->mr_list_node);

    // Iterate over all QPs and unmap this MR from their cthreads
    struct scenic_ib_qp *qp;
    list_for_each(&scenic_ctx->qp_list, qp, qp_list_node) {
        if (qp->cthread) {
            int unmap_ret = cthread_user_unmap(qp->cthread, (void *)mr->vaddr);
            if (unmap_ret) {
                printf("SCENIC IB: scenic_dereg_mr - cthread_user_unmap failed for QP %u with ret=%d\n", qp->local_qpn, unmap_ret);
            } else {
                printf("SCENIC IB: scenic_dereg_mr - Unmapped MR from QP %u cthread\n", qp->local_qpn);
            }
        }
    }
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);

    // Step 2: Call the kernel to deregister the MR
    ret = ibv_cmd_dereg_mr(vmr);
    if(ret) {
        return ret;
    }

    // Step 3: Free the memory allocated for the scenic_ib_mr structure
    free(mr);
    return 0;
}

// Function to create a CQ 
static struct ibv_cq *scenic_ib_create_cq(struct ibv_context *ibv_ctx, int cqe, struct ibv_comp_channel *channel, int comp_vector) {
    printf("SCENIC IB: scenic_ib_create_cq - Entered function\n");
    printf("SCENIC IB: scenic_ib_create_cq - cqe=%d, channel=%p, comp_vector=%d\n", cqe, channel, comp_vector);
    struct scenic_ib_cq *scenic_cq;
    struct ibv_create_cq cmd;
    struct userspace_cyt_rdma_create_cq_resp resp;
    int ret; 

    // Step 1: Allocate memory for the scenic_ib_cq structure
    scenic_cq = calloc(1, sizeof(*scenic_cq));
    if(!scenic_cq) {
        return NULL;
    }  
    printf("SCENIC IB: scenic_ib_create_cq - After calloc\n");

    // Step 2: Call the kernel to create the CQ
    ret = ibv_cmd_create_cq(ibv_ctx, cqe, channel, comp_vector, &scenic_cq->ibv_cq, &cmd, sizeof(cmd), &resp.ibv_resp, sizeof(resp));
    if(ret) {
        printf("SCENIC IB: scenic_ib_create_cq - ibv_cmd_create_cq failed with ret=%d\n", ret);
        free(scenic_cq);
        return NULL;   
    }  

    // Step 3: Store the CQ number
    printf("SCENIC IB: scenic_ib_create_cq - After ibv_cmd_create_cq\n");
    scenic_cq->cqn = resp.cqn;

    // Initialize the qp_list head
    list_head_init(&scenic_cq->qp_send_list);
    list_head_init(&scenic_cq->qp_recv_list);

    // Step 4: Store the scenic_ib_cq structure in the local list of CQs
    struct scenic_ib_context *scenic_ctx = to_scenic_ib_context(ibv_ctx);
    printf("SCENIC IB: scenic_ib_create_cq - Before adding to cq_list\n");
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    printf("SCENIC IB: scenic_ib_create_cq - Adding CQ with cqn=%u to cq_list\n", scenic_cq->cqn);
    list_add_tail(&scenic_ctx->cq_list, &scenic_cq->cq_list_node);
    printf("SCENIC IB: scenic_ib_create_cq - Added CQ to cq_list\n");
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);
    printf("SCENIC IB: scenic_ib_create_cq - After adding to cq_list\n");

    // Step 4: Return the pointer to the embedded ibv_cq structure
    return &scenic_cq->ibv_cq;
}

// Function to destroy a CQ
static int scenic_ib_destroy_cq(struct ibv_cq *ibv_cq) {
    struct scenic_ib_cq *scenic_cq = to_scenic_ib_cq(ibv_cq);
    struct scenic_ib_context *scenic_ctx = to_scenic_ib_context(ibv_cq->context);
    int ret;    

    // Step 1: Remove the CQ from the local list of CQs
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    list_del(&scenic_cq->cq_list_node);
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);

    // Step 2: Call the kernel to destroy the CQ
    ret = ibv_cmd_destroy_cq(ibv_cq);
    if(ret) {
        return ret;
    }

    // Step 3: Free the memory allocated for the scenic_ib_cq structure
    free(scenic_cq);
    return 0;
}

// Function to poll a CQ 
static int scenic_ib_poll_cq(struct ibv_cq *ibv_cq, int num_entries, struct ibv_wc *wc) {
    // To be implemented later
    return 0;
}

// Function to create a queue pair for RDMA
static struct ibv_qp *scenic_ib_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr) {
    // Step 1: Create all the necessary structures and variables
    printf("SCENIC IB: scenic_ib_create_qp - Entered function\n");
    struct scenic_ib_context *scenic_ctx = to_scenic_ib_context(pd->context);
    struct scenic_ib_qp *scenic_qp;
    struct userspace_cyt_rdma_create_qp_cmd cmd;
    struct ib_uverbs_create_qp_resp resp;
    uint32_t qpn;
    int ret;

    // Step 2: Allocate memory for the scenic_ib_qp structure, create a cthread and attach it 
    scenic_qp = calloc(1, sizeof(*scenic_qp));
    scenic_qp->cthread = cthread_create(1, getpid(), 0, NULL); 
    qpn = cthread_get_local_qpn(scenic_qp->cthread);

    // Step 3: Add the scenic_ib_qp structure to the local list of QPs in the context and for the specified CQ 
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    scenic_qp->local_qpn = qpn;
    list_add_tail(&scenic_ctx->qp_list, &scenic_qp->qp_list_node);
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);
    
    // Step 4: Iterate over the list of CQs to find the associated send and recv CQs and link the QP to them
    //Iterate over all CQs in the context
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    struct scenic_ib_cq *scenic_send_cq = to_scenic_ib_cq(attr->send_cq);
    struct scenic_ib_cq *scenic_recv_cq = to_scenic_ib_cq(attr->recv_cq);

    // Link the QP to the send CQ
    list_add_tail(&scenic_send_cq->qp_send_list, &scenic_qp->qp_list_node);
    printf("SCENIC IB: scenic_ib_create_qp - Linked QP %u to send CQ %u\n", qpn, scenic_send_cq->cqn);
    // Link the QP to the recv CQ
    list_add_tail(&scenic_recv_cq->qp_recv_list, &scenic_qp->qp_list_node);
    printf("SCENIC IB: scenic_ib_create_qp - Linked QP %u to recv CQ %u\n", qpn, scenic_recv_cq->cqn);
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);

    // Step 5: Register all existing MRs with the cthread
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    struct scenic_ib_mr *mr;
    list_for_each(&scenic_ctx->mr_list, mr, mr_list_node) {
        int map_ret = cthread_user_map(scenic_qp->cthread, (void *)mr->vaddr, (uint32_t)mr->length);
        if (map_ret) {
            printf("SCENIC IB: scenic_ib_create_qp - cthread_user_map failed for MR vaddr=0x%lx with ret=%d\n", mr->vaddr, map_ret);
        } else {
            printf("SCENIC IB: scenic_ib_create_qp - Mapped MR vaddr=0x%lx to QP %u cthread\n", mr->vaddr, qpn);
        }
    }
    pthread_mutex_unlock(&scenic_ctx->scenic_lock); 

    // Step 6: Call the kernel to create the QP 
    cmd.qpn = qpn;
    ret = ibv_cmd_create_qp(pd, &scenic_qp->ibv_qp, attr, &cmd.cmd, sizeof(cmd), &resp, sizeof(resp));
    if(ret) {
        printf("SCENIC IB: scenic_ib_create_qp - ibv_cmd_create_qp failed with ret=%d\n", ret);
        // Clean up allocated resources
        cthread_destroy(scenic_qp->cthread);

        // Remove the QP from the local list of QPs
        pthread_mutex_lock(&scenic_ctx->scenic_lock);
        list_del(&scenic_qp->qp_list_node);
        pthread_mutex_unlock(&scenic_ctx->scenic_lock);
        free(scenic_qp);
    }
    printf("SCENIC IB: scenic_ib_create_qp - Created QP with qpn=%u\n", qpn);

    return &scenic_qp->ibv_qp;
}

// Function to destroy a queue pair for RDMA
static int scenic_ib_destroy_qp(struct ibv_qp *ibv_qp) {
    printf("SCENIC IB: scenic_ib_destroy_qp - Entered function\n");

    // Step 1: Get the scenic_ib_qp and scenic_ib_context structures
    struct scenic_ib_qp *scenic_qp = to_scenic_ib_qp(ibv_qp);
    struct scenic_ib_context *scenic_ctx = to_scenic_ib_context(ibv_qp->context);
    int ret;    
    printf("SCENIC IB: scenic_ib_destroy_qp - QP qpn=%u\n", scenic_qp->local_qpn);

    // Step 2: Remove the QP from the local list of QPs in the context and from the associated CQs
    pthread_mutex_lock(&scenic_ctx->scenic_lock);
    list_del(&scenic_qp->qp_list_node);
    pthread_mutex_unlock(&scenic_ctx->scenic_lock);
    printf("SCENIC IB: scenic_ib_destroy_qp - Removed QP from qp_list\n");

    // Step 3: Destroy the associated cthread
    cthread_destroy(scenic_qp->cthread);
    printf("SCENIC IB: scenic_ib_destroy_qp - Destroyed cthread\n");

    // Step 4: Call the kernel to destroy the QP
    ret = ibv_cmd_destroy_qp(ibv_qp);
    if(ret) {
        printf("SCENIC IB: scenic_ib_destroy_qp - ibv_cmd_destroy_qp failed with ret=%d\n", ret);
        return ret;
    }

    // Step 5: Free the memory allocated for the scenic_ib_qp structure
    free(scenic_qp);

    return 0;
}

uint32_t extract_ipv4_from_gid(union ibv_gid *gid) {
    uint32_t ipv4_network_order;
    
    // Copy the last 4 bytes (Offset 12)
    memcpy(&ipv4_network_order, &gid->raw[12], sizeof(uint32_t));

    return ipv4_network_order;
}

// Function to modify a queue pair for RDMA
static int scenic_ib_modify_qp(struct ibv_qp *ibv_qp, struct ibv_qp_attr *attr, int attr_mask) {
    printf("SCENIC IB: scenic_ib_modify_qp - Entered function\n");

    // Step 1: Get the required structs
    struct scenic_ib_qp *scenic_qp = to_scenic_ib_qp(ibv_qp);
    struct scenic_ib_context *scenic_ctx = to_scenic_ib_context(ibv_qp->context);
    struct ibv_modify_qp cmd; 
    int ret; 

    memset(&cmd, 0, sizeof(cmd));

    // Step 1: Call the kernel to validate the state modification 
    ret = ibv_cmd_modify_qp(ibv_qp, attr, attr_mask, &cmd, sizeof(cmd));
    if(ret) {
        printf("SCENIC IB: scenic_ib_modify_qp - ibv_cmd_modify_qp failed with ret=%d\n", ret);
        return ret;
    }

    // Step 2: Actual implementation of state transitions including HW-interactions 
    if(attr_mask & IBV_QP_STATE) {
        switch(attr->qp_state) {
            case IBV_QPS_INIT:
                // Couldn't give a flying f 'bout access flags for now, so just focus on the port number 
                if(attr_mask & IBV_QP_PORT) {
                    scenic_qp->port = attr->port_num;
                }
                printf("SCENIC IB: scenic_ib_modify_qp - QP %u moved to INIT on port %u\n", scenic_qp->local_qpn, scenic_qp->port);
                break;
            case IBV_QPS_RTR:
                // This should give us the remote QPN, PSN and GID / IPv4. We extract all of this and then think about calling functions accordingly 
                if((attr_mask & IBV_QP_AV) && (attr_mask & IBV_QP_DEST_QPN)) {
                    scenic_qp->remote_qpn = attr->dest_qp_num;
                    scenic_qp->local_psn = (attr_mask & IBV_QP_RQ_PSN) ? attr->rq_psn : 0;
                    scenic_qp->remote_ip = extract_ipv4_from_gid(&attr->ah_attr.grh.dgid);
                    scenic_qp->remote_rkey = 0; // For now - to be set later with WR 

                    printf("SCENIC IB: scenic_ib_modify_qp - QP %u moved to RTR. Remote QPN=%u, Remote PSN=%u, Remote IP=0x%x\n", scenic_qp->local_qpn, scenic_qp->remote_qpn, scenic_qp->remote_psn, scenic_qp->remote_ip);

                    // Set up the remote QP 
                    cthread_set_remote_qp(scenic_qp->cthread, scenic_qp->remote_qpn, scenic_qp->remote_rkey, scenic_qp->remote_psn, scenic_qp->remote_ip);
                    cthread_set_local_psn(scenic_qp->cthread, scenic_qp->local_psn);

                    // Do an ARP lookup 
                    cthread_arp_lookup(scenic_qp->cthread, scenic_qp->remote_ip);

                    // Initial call to setup the connection in HW 
                    cthread_write_qp_context(scenic_qp->cthread, scenic_qp->port);
                }
                break;
            case IBV_QPS_RTS:
                // Get ourselves the local PSN and then get the fuck away from all of this state bs
                if((attr_mask & IBV_QP_SQ_PSN)) {
                    scenic_qp->remote_psn = attr->sq_psn;
                    cthread_set_remote_psn(scenic_qp->cthread, scenic_qp->remote_psn);

                    // Call the setup again to reinitialize the starting send PSN
                    cthread_write_qp_ctx(scenic_qp->cthread, scenic_qp->port, 1, 0);
                }
                break;
            default:
                printf("SCENIC IB: scenic_ib_modify_qp - Unsupported QP state %d\n", attr->qp_state);
                return -1;
        }
    }


    // To be implemented later
    return 0;
}   

// Function to post send work requests to a queue pair
static int scenic_ib_post_send(struct ibv_qp *ibv_qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr) {
    // This is one big feat -> If we master this, the path is open for glory and fame. 

    // STEP 1: Get the required structures: 
    struct scenic_ib_qp *scenic_qp = to_scenic_ib_qp(ibv_qp);
    printf("SCENIC IB: scenic_ib_post_send - Entered function for QP %u\n", scenic_qp->local_qpn);

    // STEP 2: Iterate over the linked list of work requests and process each one 
    struct ibv_send_wr *current_wr = wr;
    while(current_wr) {
        printf("SCENIC IB: scenic_ib_post_send - Processing WR with opcode %d\n", current_wr->opcode);
        switch(current_wr->opcode) {
            case IBV_WR_RDMA_WRITE:
                // What we do first: Check for the rkey and update if required 
                uint32_t rkey = wr->wr.rdma.rkey;
                if(scenic_qp->remote_rkey != rkey) {
                    scenic_qp->remote_rkey = rkey;
                    cthread_set_remote_rkey(scenic_qp->cthread, rkey);
                    cthread_write_qp_ctx(scenic_qp->cthread, scenic_qp->port, 0, 1);
                }

                // Next step: Generate all the required FPGA interactions to post the RDMA WRITE 

                // First create the coyote SG and fill out what will stay constant for all RDMA SGEs 
                struct cyt_rdma_sg_t rdma_sg; 
                rdma_sg.remote_offs = 0; 
                rdma_sg.local_stream = CYT_STRM_HOST; 
                rdma_sg.remote_dest = current_wr->wr.rdma.remote_addr;

                int accumulated_length_offset = 0; 

                // Now iterate over all SGEs in the current WR 
                for(int i = 0; i < current_wr->num_sge; i++) {
                    struct ibv_sge *sge = &current_wr->sg_list[i];

                    // Update the SGE-specific fields in the coyote SG 
                    rdma_sg.length = sge->length; 
                    rdma_sg.local_addr = sge->addr; 
                    rdma_sg.local_offs = accumulated_length_offset;
                    accumulated_length_offset += sge->length;

                    // Now post the RDMA WRITE via the cthread interface 
                    cthread_invoke_rdma(scenic_qp->cthread, CYT_RDMA_WRITE, &rdma_sg);
                }
                break;

            case IBV_WR_RDMA_READ: 
                // What we do first: Check for the rkey and update if required 
                uint32_t rkey = wr->wr.rdma.rkey;
                if(scenic_qp->remote_rkey != rkey) {
                    scenic_qp->remote_rkey = rkey;
                    cthread_set_remote_rkey(scenic_qp->cthread, rkey);
                    cthread_write_qp_ctx(scenic_qp->cthread, scenic_qp->port, 0, 1);
                }

                // Next step: Generate all the required FPGA interactions to post the RDMA READ 

                // First create the coyote SG and fill out what will stay constant for all RDMA SGEs
                struct cyt_rdma_sg_t rdma_sg;
                rdma_sg.remote_offs = 0; 
                rdma_sg.remote_addr = current_wr->wr.rdma.remote_addr;
                rdma_sg.local_stream = CYT_STRM_HOST;

                int accumulated_length_offset = 0;

                // Now iterate over all SGEs in the current WR
                for(int i = 0; i < current_wr->num_sge; i++) {
                    struct ibv_sge *sge = &current_wr->sg_list[i];

                    // Update the SGE-specific fields in the coyote SG
                    rdma_sg.length = sge->length;
                    rdma_sg.local_addr = sge->addr;
                    rdma_sg.local_offs = accumulated_length_offset;
                    accumulated_length_offset += sge->length;   

                    // Now post the RDMA READ via the cthread interface
                    cthread_invoke_rdma(scenic_qp->cthread, CYT_RDMA_READ, &rdma_sg);
                }
                break;


            default: 
                printf("SCENIC IB: scenic_ib_post_send - Unsupported WR opcode %d\n", current_wr->opcode);
                *bad_wr = current_wr;
                return -1;
        }
        current_wr = current_wr->next;
    }
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
    
    .reg_mr = scenic_reg_mr,
    .dereg_mr = scenic_dereg_mr,

    .create_cq = scenic_ib_create_cq,
    .destroy_cq = scenic_ib_destroy_cq,
    .poll_cq = scenic_ib_poll_cq,

    .create_qp = scenic_ib_create_qp,
    .destroy_qp = scenic_ib_destroy_qp,
    .modify_qp = scenic_ib_modify_qp,
    .post_send = scenic_ib_post_send,
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

    // Initialize custom fields in scenic_ib_context
    pthread_mutex_init(&scenic_ctx->scenic_lock, NULL);
    list_head_init(&scenic_ctx->qp_list);
    list_head_init(&scenic_ctx->mr_list);
    list_head_init(&scenic_ctx->cq_list);

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