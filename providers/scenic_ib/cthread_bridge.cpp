/**
 * Copyright (c) 2025, Systems Group, ETH Zurich
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

/**
 * @file cthread_bridge.cpp
 * @brief C++ implementation of the cThread C bridge
 *
 * This file implements the C-compatible wrapper functions declared in cthread_bridge.h,
 * bridging the C code in scenic_ib to the C++ cThread class.
 */

#include "cthread_bridge.h"
#include "cThread.hpp"

#include <cstring>
#include <stdexcept>

using namespace coyote;

/* Internal structure to hold the C++ cThread pointer */
struct cthread_handle {
    cThread *thread;
};

/* ============================================
 * Helper functions for type conversion
 * ============================================ */

static CoyoteOper to_coyote_oper(cyt_oper_t oper) {
    switch (oper) {
        case CYT_OPER_NOOP:              return CoyoteOper::NOOP;
        case CYT_OPER_LOCAL_READ:        return CoyoteOper::LOCAL_READ;
        case CYT_OPER_LOCAL_WRITE:       return CoyoteOper::LOCAL_WRITE;
        case CYT_OPER_LOCAL_TRANSFER:    return CoyoteOper::LOCAL_TRANSFER;
        case CYT_OPER_LOCAL_OFFLOAD:     return CoyoteOper::LOCAL_OFFLOAD;
        case CYT_OPER_LOCAL_SYNC:        return CoyoteOper::LOCAL_SYNC;
        case CYT_OPER_REMOTE_RDMA_READ:  return CoyoteOper::REMOTE_RDMA_READ;
        case CYT_OPER_REMOTE_RDMA_WRITE: return CoyoteOper::REMOTE_RDMA_WRITE;
        case CYT_OPER_REMOTE_RDMA_SEND:  return CoyoteOper::REMOTE_RDMA_SEND;
        case CYT_OPER_REMOTE_TCP_SEND:   return CoyoteOper::REMOTE_TCP_SEND;
        default:                         return CoyoteOper::NOOP;
    }
}

static CoyoteAllocType to_coyote_alloc_type(cyt_alloc_type_t type) {
    switch (type) {
        case CYT_ALLOC_REG: return CoyoteAllocType::REG;
        case CYT_ALLOC_THP: return CoyoteAllocType::THP;
        case CYT_ALLOC_HPF: return CoyoteAllocType::HPF;
        case CYT_ALLOC_PRM: return CoyoteAllocType::PRM;
        case CYT_ALLOC_GPU: return CoyoteAllocType::GPU;
        default:            return CoyoteAllocType::REG;
    }
}

static syncSg to_sync_sg(const cyt_sync_sg_t *sg) {
    syncSg result;
    result.addr = sg->addr;
    result.len = sg->len;
    return result;
}

static localSg to_local_sg(const cyt_local_sg_t *sg) {
    localSg result;
    result.addr = sg->addr;
    result.len = sg->len;
    result.stream = sg->stream;
    result.dest = sg->dest;
    return result;
}

static rdmaSg to_rdma_sg(const cyt_rdma_sg_t *sg) {
    rdmaSg result;
    result.local_offs = sg->local_offs;
    result.local_stream = sg->local_stream;
    result.local_dest = sg->local_dest;
    result.remote_offs = sg->remote_offs;
    result.remote_dest = sg->remote_dest;
    result.len = sg->len;
    return result;
}

static tcpSg to_tcp_sg(const cyt_tcp_sg_t *sg) {
    tcpSg result;
    result.stream = sg->stream;
    result.dest = sg->dest;
    result.len = sg->len;
    return result;
}

/* ============================================
 * cThread lifecycle functions
 * ============================================ */

extern "C" cthread_t cthread_create(int32_t vfid, pid_t hpid, uint32_t device, void (*uisr)(int)) {
    try {
        cthread_handle *handle = new cthread_handle;
        handle->thread = new cThread(vfid, hpid, device, uisr);
        return handle;
    } catch (const std::exception &e) {
        return nullptr;
    }
}

extern "C" void cthread_destroy(cthread_t ct) {
    if (ct) {
        delete ct->thread;
        delete ct;
    }
}

/* ============================================
 * Memory management functions
 * ============================================ */

extern "C" int cthread_user_map(cthread_t ct, void *vaddr, uint32_t len) {
    if (!ct || !ct->thread) return -1;
    try {
        ct->thread->userMap(vaddr, len);
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

extern "C" int cthread_user_unmap(cthread_t ct, void *vaddr) {
    if (!ct || !ct->thread) return -1;
    try {
        ct->thread->userUnmap(vaddr);
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

extern "C" void* cthread_get_mem(cthread_t ct, const cyt_alloc_t *alloc) {
    if (!ct || !ct->thread || !alloc) return nullptr;
    try {
        CoyoteAlloc cpp_alloc;
        cpp_alloc.alloc = to_coyote_alloc_type(alloc->alloc);
        cpp_alloc.size = alloc->size;
        cpp_alloc.remote = alloc->remote != 0;
        cpp_alloc.gpu_dev_id = alloc->gpu_dev_id;
        cpp_alloc.gpu_dmabuf_fd = alloc->gpu_dmabuf_fd;
        return ct->thread->getMem(std::move(cpp_alloc));
    } catch (const std::exception &e) {
        return nullptr;
    }
}

extern "C" int cthread_free_mem(cthread_t ct, void *vaddr) {
    if (!ct || !ct->thread) return -1;
    try {
        ct->thread->freeMem(vaddr);
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

/* ============================================
 * Control/Status Register (CSR) access
 * ============================================ */

extern "C" void cthread_set_csr(cthread_t ct, uint64_t val, uint32_t offs) {
    if (ct && ct->thread) {
        ct->thread->setCSR(val, offs);
    }
}

extern "C" uint64_t cthread_get_csr(cthread_t ct, uint32_t offs) {
    if (ct && ct->thread) {
        return ct->thread->getCSR(offs);
    }
    return 0;
}

/* ============================================
 * Data transfer invoke functions
 * ============================================ */

extern "C" int cthread_invoke_sync(cthread_t ct, cyt_oper_t oper, const cyt_sync_sg_t *sg) {
    if (!ct || !ct->thread || !sg) return -1;
    try {
        ct->thread->invoke(to_coyote_oper(oper), to_sync_sg(sg));
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

extern "C" int cthread_invoke_local(cthread_t ct, cyt_oper_t oper, const cyt_local_sg_t *sg, int last) {
    if (!ct || !ct->thread || !sg) return -1;
    try {
        ct->thread->invoke(to_coyote_oper(oper), to_local_sg(sg), last != 0);
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

extern "C" int cthread_invoke_local_transfer(cthread_t ct, cyt_oper_t oper,
                                              const cyt_local_sg_t *src_sg,
                                              const cyt_local_sg_t *dst_sg, int last) {
    if (!ct || !ct->thread || !src_sg || !dst_sg) return -1;
    try {
        ct->thread->invoke(to_coyote_oper(oper), to_local_sg(src_sg), to_local_sg(dst_sg), last != 0);
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

extern "C" int cthread_invoke_rdma(cthread_t ct, cyt_oper_t oper, const cyt_rdma_sg_t *sg, int last) {
    if (!ct || !ct->thread || !sg) return -1;
    try {
        ct->thread->invoke(to_coyote_oper(oper), to_rdma_sg(sg), last != 0);
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

extern "C" int cthread_invoke_tcp(cthread_t ct, cyt_oper_t oper, const cyt_tcp_sg_t *sg, int last) {
    if (!ct || !ct->thread || !sg) return -1;
    try {
        ct->thread->invoke(to_coyote_oper(oper), to_tcp_sg(sg), last != 0);
        return 0;
    } catch (const std::exception &e) {
        return -1;
    }
}

/* ============================================
 * Completion handling
 * ============================================ */

extern "C" uint32_t cthread_check_completed(cthread_t ct, cyt_oper_t oper) {
    if (!ct || !ct->thread) return 0;
    return ct->thread->checkCompleted(to_coyote_oper(oper));
}

extern "C" void cthread_clear_completed(cthread_t ct) {
    if (ct && ct->thread) {
        ct->thread->clearCompleted();
    }
}

/* ============================================
 * RDMA connection functions
 * ============================================ */

extern "C" void cthread_conn_sync(cthread_t ct, int client) {
    if (ct && ct->thread) {
        ct->thread->connSync(client != 0);
    }
}

extern "C" void* cthread_init_rdma(cthread_t ct, uint32_t buffer_size, uint16_t port, const char *server_address) {
    if (!ct || !ct->thread) return nullptr;
    try {
        return ct->thread->initRDMA(buffer_size, port, server_address);
    } catch (const std::exception &e) {
        return nullptr;
    }
}

extern "C" void cthread_close_conn(cthread_t ct) {
    if (ct && ct->thread) {
        ct->thread->closeConn();
    }
}

extern "C" void cthread_write_qp_context(cthread_t ct, uint32_t port) {
    if (ct && ct->thread) {
        ct->thread->writeQpContext(port);
    }
}

extern "C" void cthread_write_qp_ctx(cthread_t ct, uint32_t port, int write_rpsn, int write_rkey) {
    if (ct && ct->thread) {
        ct->thread->writeQpCtx(port, write_rpsn != 0, write_rkey != 0);
    }
}

extern "C" void cthread_write_qp_connection(cthread_t ct, uint32_t port) {
    if (ct && ct->thread) {
        ct->thread->writeQpConnection(port);
    }
}

extern "C" void cthread_arp_lookup(cthread_t ct, uint32_t ip_addr) {
    if (ct && ct->thread) {
        ct->thread->doArpLookup(ip_addr);
    }
}

extern "C" void cthread_set_local_qp(cthread_t ct, uint32_t qpn, uint32_t rkey, uint32_t psn, uint32_t ip_addr) {
    if (ct && ct->thread) {
        ct->thread->setLocalQp(qpn, rkey, psn, ip_addr);
    }
}

extern "C" void cthread_set_remote_qp(cthread_t ct, uint32_t qpn, uint32_t rkey, uint32_t psn, uint32_t ip_addr) {
    if (ct && ct->thread) {
        ct->thread->setRemoteQp(qpn, rkey, psn, ip_addr);
    }
}

extern "C" void cthread_set_remote_rkey(cthread_t ct, uint32_t rkey) {
    if (ct && ct->thread) {
        ct->thread->setRemoteRkey(rkey);
    }
}

extern "C" void cthread_set_local_psn(cthread_t ct, uint32_t psn) {
    if (ct && ct->thread) {
        ct->thread->setLocalPSN(psn);
    }
}

extern "C" void cthread_set_remote_psn(cthread_t ct, uint32_t psn) {
    if (ct && ct->thread) {
        ct->thread->setRemotePSN(psn);
    }
}

/* ============================================
 * Locking functions
 * ============================================ */

extern "C" void cthread_lock(cthread_t ct) {
    if (ct && ct->thread) {
        ct->thread->lock();
    }
}

extern "C" void cthread_unlock(cthread_t ct) {
    if (ct && ct->thread) {
        ct->thread->unlock();
    }
}

/* ============================================
 * Getter functions
 * ============================================ */

extern "C" int32_t cthread_get_vfid(cthread_t ct) {
    if (ct && ct->thread) {
        return ct->thread->getVfid();
    }
    return -1;
}

extern "C" int32_t cthread_get_ctid(cthread_t ct) {
    if (ct && ct->thread) {
        return ct->thread->getCtid();
    }
    return -1;
}

extern "C" pid_t cthread_get_hpid(cthread_t ct) {
    if (ct && ct->thread) {
        return ct->thread->getHpid();
    }
    return 0;
}

extern "C" int cthread_get_fpga_cnfg(cthread_t ct, cyt_fpga_cnfg_t *cnfg) {
    if (!ct || !ct->thread || !cnfg) return -1;

    /* Note: fcnfg is protected, so we need to access it through the class
     * For now, return -1 as the fpgaCnfg is not exposed via public interface
     * This would require either making fcnfg public or adding a getter to cThread
     */
    return -1;
}

extern "C" int cthread_get_local_qp(cthread_t ct, cyt_ibv_q_t *q) {
    if (!ct || !ct->thread || !q) return -1;

    q->ip_addr = ct->thread->getLocalQpInfo().ip_addr;
    q->qpn = ct->thread->getLocalQpInfo().qpn;
    q->psn = ct->thread->getLocalQpInfo().psn;
    q->rkey = ct->thread->getLocalQpInfo().rkey;
    q->vaddr = ct->thread->getLocalQpInfo().vaddr;
    q->size = ct->thread->getLocalQpInfo().size;
    std::memcpy(q->gid, ct->thread->getLocalQpInfo().gid, 33);
    return 0;
}

extern "C" int cthread_get_local_qpn(cthread_t ct) {
    if (!ct || !ct->thread) return -1;
    return ct->thread->getLocalQpInfo().qpn;
}  

extern "C" int cthread_get_remote_qp(cthread_t ct, cyt_ibv_q_t *q) {
    if (!ct || !ct->thread || !q) return -1;

    q->ip_addr = ct->thread->getRemoteQpInfo().ip_addr;
    q->qpn = ct->thread->getRemoteQpInfo().qpn;
    q->psn = ct->thread->getRemoteQpInfo().psn;
    q->rkey = ct->thread->getRemoteQpInfo().rkey;
    q->vaddr = ct->thread->getRemoteQpInfo().vaddr;
    q->size = ct->thread->getRemoteQpInfo().size;
    std::memcpy(q->gid, ct->thread->getRemoteQpInfo().gid, 33); 
    return 0;
}

extern "C" int cthread_get_remote_qpn(cthread_t ct) {
    if (!ct || !ct->thread) return -1;
    return ct->thread->getRemoteQpInfo().qpn;
}

/* ============================================
 * Debug functions
 * ============================================ */

extern "C" void cthread_print_debug(cthread_t ct) {
    if (ct && ct->thread) {
        ct->thread->printDebug();
    }
}
