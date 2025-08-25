// SPDX-FileCopyrightText: Copyright 2019 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

/* This file is a reference template for implementation of the
 * PSA Certified Secure Storage API v1.0.1
 *
 * This file includes common definitions
 */

#ifndef PSA_STORAGE_COMMON_H
#define PSA_STORAGE_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Flags used when creating a data entry.
 */
typedef uint32_t psa_storage_create_flags_t;

/**
 * @brief A container for metadata associated with a specific uid.
 */
struct psa_storage_info_t {
    /// @brief The allocated capacity of the storage associated with a uid.
    size_t capacity;
    /// @brief The size of the data associated with a uid.
    size_t size;
    /// @brief The flags set when the uid was create
    psa_storage_create_flags_t flags;
};



/**
 * @brief A type for uid used for identifying data.
 */
typedef uint64_t psa_storage_uid_t;
#define PSA_STORAGE_FLAG_NONE 0u
#define PSA_STORAGE_FLAG_WRITE_ONCE (1u << 0)
#define PSA_STORAGE_FLAG_NO_CONFIDENTIALITY (1u << 1)
#define PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION (1u << 2)
#define PSA_STORAGE_SUPPORT_SET_EXTENDED (1u << 0)

#ifdef __cplusplus
}
#endif

#endif // PSA_STORAGE_COMMON_H
