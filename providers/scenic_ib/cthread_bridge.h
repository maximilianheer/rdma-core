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
 * @file cthread_bridge.h
 * @brief C bridge header for exposing cThread C++ functionality to C code
 *
 * This header provides a C-compatible interface to the Coyote cThread class,
 * allowing the scenic_ib rdma-core provider to interact with the vFPGA.
 */

#ifndef CTHREAD_BRIDGE_H
#define CTHREAD_BRIDGE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================
 * Opaque handle for the C++ cThread object
 * ============================================ */
typedef struct cthread_handle* cthread_t;

/* ============================================
 * C-compatible type definitions
 * ============================================ */

/**
 * @brief Coyote operation types (mirrors CoyoteOper enum)
 */
typedef enum {
    CYT_OPER_NOOP = 0,
    CYT_OPER_LOCAL_READ = 1,
    CYT_OPER_LOCAL_WRITE = 2,
    CYT_OPER_LOCAL_TRANSFER = 3,
    CYT_OPER_LOCAL_OFFLOAD = 4,
    CYT_OPER_LOCAL_SYNC = 5,
    CYT_OPER_REMOTE_RDMA_READ = 6,
    CYT_OPER_REMOTE_RDMA_WRITE = 7,
    CYT_OPER_REMOTE_RDMA_SEND = 8,
    CYT_OPER_REMOTE_TCP_SEND = 9
} cyt_oper_t;

/**
 * @brief Memory allocation types (mirrors CoyoteAllocType enum)
 */
typedef enum {
    CYT_ALLOC_REG = 0,  /* Regular pages (4KB) */
    CYT_ALLOC_THP = 1,  /* Transparent huge pages */
    CYT_ALLOC_HPF = 2,  /* Huge pages (2MB) */
    CYT_ALLOC_PRM = 3,  /* Partial reconfiguration memory */
    CYT_ALLOC_GPU = 4   /* GPU memory */
} cyt_alloc_type_t;

/**
 * @brief Stream constants
 */
#define CYT_STRM_CARD 0
#define CYT_STRM_HOST 1
#define CYT_STRM_RDMA 2
#define CYT_STRM_TCP  3

/**
 * @brief Memory allocation parameters (mirrors CoyoteAlloc struct)
 */
typedef struct {
    cyt_alloc_type_t alloc;     /* Type of allocation */
    uint32_t size;              /* Size in bytes */
    int remote;                 /* Non-zero if used for remote operations */
    uint32_t gpu_dev_id;        /* GPU device ID (for GPU allocs) */
    int32_t gpu_dmabuf_fd;      /* DMA buffer fd (for GPU allocs) */
} cyt_alloc_t;

/**
 * @brief Scatter-gather entry for sync/offload operations (mirrors syncSg)
 */
typedef struct {
    void *addr;      /* Buffer address */
    uint64_t len;    /* Buffer length in bytes */
} cyt_sync_sg_t;

/**
 * @brief Scatter-gather entry for local operations (mirrors localSg)
 */
typedef struct {
    void *addr;      /* Buffer address */
    uint32_t len;    /* Buffer length in bytes */
    uint32_t stream; /* HOST or CARD stream */
    uint32_t dest;   /* Destination stream index */
} cyt_local_sg_t;

/**
 * @brief Scatter-gather entry for RDMA operations (mirrors rdmaSg)
 */
typedef struct {
    uint64_t local_offs;    /* Offset from local buffer address */
    uint32_t local_stream;  /* Source buffer stream (HOST or CARD) */
    uint32_t local_dest;    /* Local destination stream index */
    uint64_t remote_offs;   /* Offset for remote buffer */
    uint32_t remote_dest;   /* Remote destination stream index */
    uint32_t len;           /* Transfer length in bytes */
} cyt_rdma_sg_t;

/**
 * @brief Scatter-gather entry for TCP operations (mirrors tcpSg)
 */
typedef struct {
    uint32_t stream;  /* TCP stream */
    uint32_t dest;    /* Destination */
    uint32_t len;     /* Transfer length */
} cyt_tcp_sg_t;

/**
 * @brief RDMA Queue information (mirrors ibvQ struct)
 */
typedef struct {
    uint32_t ip_addr;   /* Node IP address */
    uint32_t qpn;       /* Queue Pair Number */
    uint32_t psn;       /* Packet Serial Number */
    uint32_t rkey;      /* Memory rkey */
    void *vaddr;        /* Buffer virtual address */
    uint32_t size;      /* Buffer size */
    char gid[33];       /* Global ID */
} cyt_ibv_q_t;

/**
 * @brief FPGA configuration (mirrors fpgaCnfg struct)
 */
typedef struct {
    int en_avx;         /* AVX enabled */
    int en_wb;          /* Writeback enabled */
    int en_strm;        /* Host streams enabled */
    int en_mem;         /* FPGA memory streams enabled */
    int en_pr;          /* Partial reconfiguration enabled */
    int en_rdma;        /* RDMA enabled */
    int en_tcp;         /* TCP enabled */
    int en_net;         /* Network enabled (RDMA or TCP) */
    int32_t n_xdma_chan;/* Number of XDMA channels */
    int32_t n_fpga_reg; /* Number of vFPGAs */
} cyt_fpga_cnfg_t;

/* ============================================
 * cThread lifecycle functions
 * ============================================ */

/**
 * @brief Create a new cThread instance
 *
 * @param vfid Virtual FPGA ID
 * @param hpid Host process ID
 * @param device Device number (for multi-FPGA systems)
 * @param uisr User interrupt service routine (can be NULL)
 * @return Handle to the created cThread, or NULL on failure
 */
cthread_t cthread_create(int32_t vfid, pid_t hpid, uint32_t device, void (*uisr)(int));

/**
 * @brief Destroy a cThread instance
 *
 * @param ct Handle to the cThread to destroy
 */
void cthread_destroy(cthread_t ct);


/* ============================================
 * Memory management functions
 * ============================================ */

/**
 * @brief Map a user buffer to the vFPGA's TLB
 *
 * @param ct cThread handle
 * @param vaddr Virtual address of the buffer
 * @param len Buffer length in bytes
 * @return 0 on success, negative error code on failure
 */
int cthread_user_map(cthread_t ct, void *vaddr, uint32_t len);

/**
 * @brief Unmap a buffer from the vFPGA's TLB
 *
 * @param ct cThread handle
 * @param vaddr Virtual address of the buffer to unmap
 * @return 0 on success, negative error code on failure
 */
int cthread_user_unmap(cthread_t ct, void *vaddr);

/**
 * @brief Allocate memory and map it to the vFPGA's TLB
 *
 * @param ct cThread handle
 * @param alloc Allocation parameters
 * @return Pointer to allocated memory, or NULL on failure
 */
void* cthread_get_mem(cthread_t ct, const cyt_alloc_t *alloc);

/**
 * @brief Free and unmap previously allocated memory
 *
 * @param ct cThread handle
 * @param vaddr Virtual address of the buffer to free
 * @return 0 on success, negative error code on failure
 */
int cthread_free_mem(cthread_t ct, void *vaddr);

/* ============================================
 * Control/Status Register (CSR) access
 * ============================================ */

/**
 * @brief Set a control register value
 *
 * @param ct cThread handle
 * @param val Value to write
 * @param offs Register offset
 */
void cthread_set_csr(cthread_t ct, uint64_t val, uint32_t offs);

/**
 * @brief Read a control register value
 *
 * @param ct cThread handle
 * @param offs Register offset
 * @return Register value
 */
uint64_t cthread_get_csr(cthread_t ct, uint32_t offs);

/* ============================================
 * Data transfer invoke functions
 * ============================================ */

/**
 * @brief Invoke a sync or offload operation
 *
 * @param ct cThread handle
 * @param oper Operation (CYT_OPER_LOCAL_SYNC or CYT_OPER_LOCAL_OFFLOAD)
 * @param sg Scatter-gather entry
 * @return 0 on success, negative error code on failure
 */
int cthread_invoke_sync(cthread_t ct, cyt_oper_t oper, const cyt_sync_sg_t *sg);

/**
 * @brief Invoke a one-sided local operation
 *
 * @param ct cThread handle
 * @param oper Operation (CYT_OPER_LOCAL_READ or CYT_OPER_LOCAL_WRITE)
 * @param sg Scatter-gather entry
 * @param last Non-zero if this is the last operation in sequence
 * @return 0 on success, negative error code on failure
 */
int cthread_invoke_local(cthread_t ct, cyt_oper_t oper, const cyt_local_sg_t *sg, int last);

/**
 * @brief Invoke a two-sided local transfer operation
 *
 * @param ct cThread handle
 * @param oper Operation (CYT_OPER_LOCAL_TRANSFER)
 * @param src_sg Source scatter-gather entry
 * @param dst_sg Destination scatter-gather entry
 * @param last Non-zero if this is the last operation in sequence
 * @return 0 on success, negative error code on failure
 */
int cthread_invoke_local_transfer(cthread_t ct, cyt_oper_t oper,
                                  const cyt_local_sg_t *src_sg,
                                  const cyt_local_sg_t *dst_sg, int last);

/**
 * @brief Invoke an RDMA operation
 *
 * @param ct cThread handle
 * @param oper Operation (CYT_OPER_REMOTE_RDMA_READ or CYT_OPER_REMOTE_RDMA_WRITE)
 * @param sg RDMA scatter-gather entry
 * @param last Non-zero if this is the last operation in sequence
 * @return 0 on success, negative error code on failure
 */
int cthread_invoke_rdma(cthread_t ct, cyt_oper_t oper, const cyt_rdma_sg_t *sg, int last);

/**
 * @brief Invoke a TCP operation
 *
 * @param ct cThread handle
 * @param oper Operation (CYT_OPER_REMOTE_TCP_SEND)
 * @param sg TCP scatter-gather entry
 * @param last Non-zero if this is the last operation in sequence
 * @return 0 on success, negative error code on failure
 */
int cthread_invoke_tcp(cthread_t ct, cyt_oper_t oper, const cyt_tcp_sg_t *sg, int last);

/* ============================================
 * Completion handling
 * ============================================ */

/**
 * @brief Check the number of completed operations
 *
 * @param ct cThread handle
 * @param oper Operation type to query
 * @return Number of completed operations since last clearCompleted()
 */
uint32_t cthread_check_completed(cthread_t ct, cyt_oper_t oper);

/**
 * @brief Clear all completion counters
 *
 * @param ct cThread handle
 */
void cthread_clear_completed(cthread_t ct);

/* ============================================
 * RDMA connection functions
 * ============================================ */

/**
 * @brief Synchronize connection between client and server
 *
 * @param ct cThread handle
 * @param client Non-zero if this is the client side
 */
void cthread_conn_sync(cthread_t ct, int client);

/**
 * @brief Initialize RDMA operations
 *
 * Creates an out-of-band connection and allocates an RDMA buffer.
 *
 * @param ct cThread handle
 * @param buffer_size Size of buffer to allocate
 * @param port Port number for out-of-band connection
 * @param server_address Server address (NULL if acting as server)
 * @return Pointer to allocated RDMA buffer, or NULL on failure
 */
void* cthread_init_rdma(cthread_t ct, uint32_t buffer_size, uint16_t port, const char *server_address);

/**
 * @brief Close the RDMA out-of-band connection
 *
 * @param ct cThread handle
 */
void cthread_close_conn(cthread_t ct);

/**
 * @brief Write the RDMA QP context to the vFPGA
 */
void cthread_write_qp_context(cthread_t ct, uint32_t port); 

/**
 * @brief Write the RDMA QP Ctx to the RDMA-stack 
 */
void cthread_write_qp_ctx(cthread_t ct, uint32_t port, int write_rpsn, int write_rkey);

/**
 * @brief Write the RDMA QP connection to the RDMA stack
 */
void cthread_write_qp_connection(cthread_t ct, uint32_t port);

/**
 * @brief Perform ARP lookup for a given IP address
 */
void cthread_arp_lookup(cthread_t ct, uint32_t ip_addr); 

/**
 * @brief Sets the local RDMA QP information in the vFPGA 
 */
void cthread_set_local_qp(cthread_t ct, uint32_t qpn, uint32_t rkey, uint32_t psn, uint32_t ip_addr);

/**
 * @brief Sets the remote RDMA QP information in the vFPGA 
 */
void cthread_set_remote_qp(cthread_t ct, uint32_t qpn, uint32_t rkey, uint32_t psn, uint32_t ip_addr);

/**
 * @brief Sets the remote RDMA rkey in the vFPGA 
 */
void cthread_set_remote_rkey(cthread_t ct, uint32_t rkey);

/**
 * @brief Sets the local RDMA PSN in the vFPGA 
 */
void cthread_set_local_psn(cthread_t ct, uint32_t psn);


/* ============================================
 * Locking functions
 * ============================================ */

/**
 * @brief Lock the vFPGA for exclusive access
 *
 * @param ct cThread handle
 */
void cthread_lock(cthread_t ct);

/**
 * @brief Unlock the vFPGA
 *
 * @param ct cThread handle
 */
void cthread_unlock(cthread_t ct);

/* ============================================
 * Getter functions
 * ============================================ */

/**
 * @brief Get the virtual FPGA ID
 *
 * @param ct cThread handle
 * @return vFPGA ID
 */
int32_t cthread_get_vfid(cthread_t ct);

/**
 * @brief Get the Coyote thread ID
 *
 * @param ct cThread handle
 * @return Coyote thread ID
 */
int32_t cthread_get_ctid(cthread_t ct);

/**
 * @brief Get the host process ID
 *
 * @param ct cThread handle
 * @return Host process ID
 */
pid_t cthread_get_hpid(cthread_t ct);

/**
 * @brief Get the FPGA configuration
 *
 * @param ct cThread handle
 * @param cnfg Pointer to structure to fill with configuration
 * @return 0 on success, negative error code on failure
 */
int cthread_get_fpga_cnfg(cthread_t ct, cyt_fpga_cnfg_t *cnfg);

/**
 * @brief Get the local RDMA queue information
 *
 * @param ct cThread handle
 * @param q Pointer to structure to fill with queue info
 * @return 0 on success, negative error code on failure
 */
int cthread_get_local_qp(cthread_t ct, cyt_ibv_q_t *q);

/**
 * @brief Get the remote RDMA queue information
 *
 * @param ct cThread handle
 * @param q Pointer to structure to fill with queue info
 * @return 0 on success, negative error code on failure
 */
int cthread_get_remote_qp(cthread_t ct, cyt_ibv_q_t *q);

/**
 * @brief Return the local QPN
 */
int cthread_get_local_qpn(cthread_t ct);

/**
 * @brief Return the remote QPN
 */
int cthread_get_remote_qpn(cthread_t ct);

/* ============================================
 * Debug functions
 * ============================================ */

/**
 * @brief Print debug information about the cThread
 *
 * @param ct cThread handle
 */
void cthread_print_debug(cthread_t ct);

#ifdef __cplusplus
}
#endif

#endif /* CTHREAD_BRIDGE_H */
