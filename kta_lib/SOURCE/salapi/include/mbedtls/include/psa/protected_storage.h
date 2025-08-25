// SPDX-FileCopyrightText: Copyright 2019 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

/* This file is a reference template for implementation of the
 * PSA Certified Secure Storage API v1.0.1
 *
 * This file describes the Protected Storage API
 */

#ifndef PSA_PROTECTED_STORAGE_H
#define PSA_PROTECTED_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief The major version number of the Protected Storage API.
 */
#define PSA_PS_API_VERSION_MAJOR 1

/**
 * @brief The minor version number of the Protected Storage API.
 */
#define PSA_PS_API_VERSION_MINOR 0

/**
 * @brief Set the data associated with the specified uid.
 *
 * @param uid          The identifier for the data.
 * @param data_length  The size in bytes of the data in p_data.
 * @param p_data       A buffer containing the data.
 * @param create_flags The flags indicating the properties of the data.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_ps_set(psa_storage_uid_t uid,
                        size_t data_length,
                        const void * p_data,
                        psa_storage_create_flags_t create_flags);

/**
 * @brief Retrieve data associated with a provided uid.
 *
 * @param uid           The uid value.
 * @param data_offset   The starting offset of the data requested.
 * @param data_size     The amount of data requested.
 * @param p_data        On success, the buffer where the data will be placed.
 * @param p_data_length On success, will contain size of the data placed in
 *                      p_data.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_ps_get(psa_storage_uid_t uid,
                        size_t data_offset,
                        size_t data_size,
                        void * p_data,
                        size_t * p_data_length);

/**
 * @brief Retrieve the metadata about the provided uid.
 *
 * @param uid    The identifier for the data.
 * @param p_info A pointer to the psa_storage_info_t struct that will be
 *               populated with the metadata.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_ps_get_info(psa_storage_uid_t uid,
                             struct psa_storage_info_t * p_info);

/**
 * @brief Remove the provided uid and its associated data from the storage.
 *
 * @param uid The identifier for the data to be removed.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_ps_remove(psa_storage_uid_t uid);

/**
 * @brief Reserves storage for the specified uid.
 *
 * @param uid          A unique identifier for the asset.
 * @param capacity     The allocated capacity, in bytes, of the uid.
 * @param create_flags Flags indicating properties of the storage.
 */
psa_status_t psa_ps_create(psa_storage_uid_t uid,
                           size_t capacity,
                           psa_storage_create_flags_t create_flags);

/**
 * @brief Overwrite part of the data of the specified uid.
 *
 * @param uid         The unique identifier for the asset.
 * @param data_offset Offset within the asset to start the write.
 * @param data_length The size in bytes of the data in p_data to write.
 * @param p_data      Pointer to a buffer which contains the data to write.
 */
psa_status_t psa_ps_set_extended(psa_storage_uid_t uid,
                                 size_t data_offset,
                                 size_t data_length,
                                 const void * p_data);

/**
 * @brief Returns a bitmask with flags set for the optional features supported
 *        by the implementation.
 */
uint32_t psa_ps_get_support(void);

#ifdef __cplusplus
}
#endif

#endif // PSA_PROTECTED_STORAGE_H
