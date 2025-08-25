// SPDX-FileCopyrightText: Copyright 2019 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

/* This file is a reference template for implementation of the
 * PSA Certified Secure Storage API v1.0.1
 *
 * This file describes the Internal Trusted Storage API
 */

#ifndef PSA_INTERNAL_TRUSTED_STORAGE_H
#define PSA_INTERNAL_TRUSTED_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief The major version number of the Internal Trusted Storage API.
 */
#define PSA_ITS_API_VERSION_MAJOR 1

/**
 * @brief The minor version number of the Internal Trusted Storage API.
 */
#define PSA_ITS_API_VERSION_MINOR 0

/**
 * @brief Set the data associated with the specified uid.
 *
 * @param uid          The identifier for the data.
 * @param data_length  The size in bytes of the data in p_data.
 * @param p_data       A buffer of data_length containing the data to store.
 * @param create_flags The flags that the data will be stored with.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_its_set(psa_storage_uid_t uid,
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
 * @param p_data_length On success, this will contain size of the data placed in
 *                      p_data.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_its_get(psa_storage_uid_t uid,
                         size_t data_offset,
                         size_t data_size,
                         void * p_data,
                         size_t * p_data_length);

/**
 * @brief Retrieve the metadata about the provided uid.
 *
 * @param uid    The uid value.
 * @param p_info A pointer to the psa_storage_info_t struct that will be
 *               populated with the metadata.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_its_get_info(psa_storage_uid_t uid,
                              struct psa_storage_info_t * p_info);

/**
 * @brief Remove the provided uid and its associated data from the storage.
 *
 * @param uid The uid value.
 *
 * @return A status indicating the success or failure of the operation.
 */
psa_status_t psa_its_remove(psa_storage_uid_t uid);

#ifdef __cplusplus
}
#endif

#endif // PSA_INTERNAL_TRUSTED_STORAGE_H
