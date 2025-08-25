/**********************************************************************************
*************************keySTREAM Trusted Agent ("KTA")***************************

* (c) 2023-2025 Nagravision Sàrl

* Subject to your compliance with these terms, you may use the Nagravision Sàrl and
* any derivatives exclusively with Nagravision's products. It is your responsibility
* to comply with third party license terms applicable to your use of third party
* software (including open source software) that mayaccompany Nagravision Software.

* Redistribution of this Nagravision Software in source or binary form is allowed
* and must include the above terms of use and the following disclaimer with the
* distribution and accompanying materials.

* THIS SOFTWARE IS SUPPLIED BY NAGRAVISION "AS IS". NO WARRANTIES, WHETHER EXPRESS,
* IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED WARRANTIES OF
* NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A PARTICULAR PURPOSE. IN NO
* EVENT WILL NAGRAVISION BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE, INCIDENTAL
* OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND WHATSOEVER RELATED TO
* THE SOFTWARE, HOWEVER CAUSED, EVEN IF NAGRAVISION HAS BEEN ADVISED OF THE
* POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW,
* NAGRAVISION'S TOTAL LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS
* SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY
* TO NAGRAVISION FOR THIS SOFTWARE.
***********************************************************************************/
/** \brief  Crypto config for Generic PSA - PROD.
 *
 *  \author Kudelski IoT
 *
 *  \date 2023/06/12
 *
 *  \file cryptoConfig.h
 ******************************************************************************/

#ifndef CRYPTOCONFIG_H
#define CRYPTOCONFIG_H

#ifdef __cplusplus
extern "C" {
#endif // C++
/* -------------------------------------------------------------------------- */
/* IMPORTS                                                                    */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* CONSTANTS, TYPES, ENUM                                                     */
/* -------------------------------------------------------------------------- */

//Server Dos PK
#define C_KTA__KS_S_DOS_PK {0xC6, 0xE9, 0x51, 0x5F, 0xAB, 0xB5, 0x94, 0xE2, \
                            0x2D, 0x1F, 0x04, 0x2B, 0x70, 0x7D, 0x67, 0x90, \
                            0x01, 0x82, 0x8C, 0xC8, 0xF4, 0xBC, 0xF6, 0x3C, \
                            0x74, 0xF8, 0xB1, 0x37, 0x6F, 0xF5, 0x38, 0x70, \
                            0x47, 0xB9, 0xE5, 0xFA, 0x9D, 0x51, 0x24, 0x82, \
                            0x44, 0xDE, 0xF8, 0x1E, 0x29, 0xF7, 0x14, 0x2B, \
                            0x59, 0xE2, 0xEE, 0x41, 0x2D, 0xB0, 0xCE, 0x9B, \
                            0x5E, 0x74, 0x4B, 0xE0, 0xE0, 0x38, 0x94, 0x45  \
                           }
#define C_KTA__KS_S_DOS_PK_SIZE 64

//Activation key fixed info
#define C_KTA__ACT_KEY_FIXED_INFO {0x31, 0xde, 0xca, 0xd8, 0x3b, 0x21, 0x1c, 0x12, \
                                   0x69, 0xa8, 0xa9, 0x84, 0x28, 0x8c, 0xa6, 0x53, \
                                   0xbf, 0x98, 0xc3, 0x0d, 0x59  \
                                  }
#define C_KTA__ACT_KEY_FIXED_INFO_SIZE 21

//Input data for activation enc key
#define C_KTA__ACT_L2_ENC_INPUT_DATA {0xa9, 0x32, 0x30, 0x31, 0x38, 0x4e, 0x61, 0x67, \
                                      0x72, 0x61, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, \
                                      0x00, 0x4c, 0x31, 0x4b, 0x65, 0x79, 0x47, 0x65, \
                                      0x6e, 0x53, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x1d, \
                                      0x54, 0x50, 0xfd, 0x8e, 0x6a, 0xb0, 0x19, 0x51, \
                                      0xfe, 0x31, 0xbb, 0xa8, 0x63, 0x6a, 0x29, 0x30, \
                                      0x00, 0x32, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, \
                                      0x00, 0x00, 0x01, 0x00  \
                                     }
#define C_KTA__ACT_L2_ENC_INPUT_DATA_SIZE 60

//Input data for activation auth key
#define C_KTA__ACT_L2_AUTH_INPUT_DATA {0xa9, 0x32, 0x30, 0x31, 0x38, 0x4e, 0x61, 0x67, \
                                       0x72, 0x61, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, \
                                       0x00, 0x4c, 0x31, 0x4b, 0x65, 0x79, 0x47, 0x65, \
                                       0x6e, 0x53, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x92, \
                                       0x81, 0x19, 0x3a, 0x97, 0xa6, 0x24, 0x64, 0x5f, \
                                       0x79, 0x18, 0x47, 0xcc, 0x6e, 0x52, 0x54, 0x30, \
                                       0x06, 0x32, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, \
                                       0x00, 0x00, 0x01, 0x00  \
                                      }
#define C_KTA__ACT_L2_AUTH_INPUT_DATA_SIZE 60

//Server PK
#define C_KTA__KS_S_PK {0xD6, 0xED, 0xD1, 0x69, 0x4A, 0x5B, 0x9B, 0x93, \
                        0xD1, 0x63, 0xAC, 0xA9, 0xAB, 0x25, 0x69, 0xF0, \
                        0xBC, 0xD6, 0x42, 0xE4, 0x5A, 0x9E, 0x47, 0x43, \
                        0x8B, 0xD4, 0x91, 0x14, 0x93, 0xB7, 0x38, 0x38, \
                        0xA1, 0x57, 0x1E, 0x26, 0x49, 0xA9, 0x46, 0xE4, \
                        0x59, 0xC2, 0x52, 0xAA, 0xE0, 0x6E, 0x4F, 0x4A, \
                        0x79, 0x0E, 0xAD, 0x78, 0x21, 0x3E, 0x53, 0x2E, \
                        0x87, 0x27, 0x7B, 0xE0, 0xB9, 0xB8, 0xAB, 0x95  \
                       }
#define C_KTA__KS_S_PK_SIZE 64

//Field key salt
#define C_KTA__FIELD_KEY_SALT {0xC7, 0x08, 0x36, 0xA7, 0xCE, 0x53, 0x72, 0xA2, \
                               0x56, 0x3D, 0x08, 0x56, 0x6D, 0xCB, 0xF0, 0xA5  \
                              }
#define C_KTA__FIELD_KEY_SALT_SIZE 16

//Field key fixed info. Replace segmentation seed provided by application at index 55 (16 bytes)
#define C_KTA__FIELD_KEY_FIXED_INFO {0xa9, 0x4e, 0x61, 0x67, 0x72, 0x61, 0x76, 0x69, \
                                     0x73, 0x69, 0x6f, 0x6e, 0x54, 0x72, 0x75, 0x73, \
                                     0x74, 0x4d, 0x2d, 0x4f, 0x6e, 0x62, 0x6f, 0x61, \
                                     0x72, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x4c, 0x30, \
                                     0x74, 0x6f, 0x4c, 0x31, 0x4b, 0x65, 0x79, 0x1d, \
                                     0xb9, 0x1e, 0xae, 0xdb, 0x38, 0xab, 0x2b, 0x70, \
                                     0xf7, 0xe8, 0x91, 0x57, 0xdb, 0x42, 0xc6, 0x00, \
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, \
                                     0x41, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, \
                                     0x02, 0x01, 0x00  \
                                    }
#define C_KTA__FIELD_KEY_FIXED_INFO_SIZE 83

//Input data for field enc key
#define C_KTA__FIELD_L2_ENC_INPUT_DATA {0xa9, 0x32, 0x30, 0x31, 0x38, 0x4e, 0x61, 0x67, \
                                        0x72, 0x61, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, \
                                        0x00, 0x4c, 0x31, 0x4b, 0x65, 0x79, 0x47, 0x65, \
                                        0x6e, 0x53, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x1d, \
                                        0x54, 0x50, 0xfd, 0x8e, 0x6a, 0xb0, 0x19, 0x51, \
                                        0xfe, 0x31, 0xbb, 0xa8, 0x63, 0x6a, 0x29, 0x20, \
                                        0x00, 0x32, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, \
                                        0x00, 0x00, 0x01, 0x00  \
                                       }
#define C_KTA__FIELD_L2_ENC_INPUT_DATA_SIZE 60

//Input data for field auth key
#define C_KTA__FIELD_L2_AUTH_INPUT_DATA {0xa9, 0x32, 0x30, 0x31, 0x38, 0x4e, 0x61, 0x67, \
                                         0x72, 0x61, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, \
                                         0x00, 0x4c, 0x31, 0x4b, 0x65, 0x79, 0x47, 0x65, \
                                         0x6e, 0x53, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x92, \
                                         0x81, 0x19, 0x3a, 0x97, 0xa6, 0x24, 0x64, 0x5f, \
                                         0x79, 0x18, 0x47, 0xcc, 0x6e, 0x52, 0x54, 0x20, \
                                         0x06, 0x32, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, \
                                         0x00, 0x00, 0x01, 0x00  \
                                        }
#define C_KTA__FIELD_L2_AUTH_IN_DATA_SIZE 60

//Rot Sol Id
#define C_KTA__ROT_SOL_ID {0x00, 0x1F  \
                          }
#define C_KTA__ROT_SOL_ID_SIZE 2

//Position to start updating segmentation seed provided by application
#define C_KTA__FIELD_KEY_FIXED_INFO_L1SEGSEED_POS 55

// Vendor specific maximum buffer size for icpp messages
#define C_K__ICPP_MSG_MAX_SIZE          1400U

// Vendor specific chip certificate size
#define C_K__CHIP_CERT_MAX_SIZE_VENDOR_SPECIFIC  1400

// Vendor specific command response size (Obj Mgnt)
#define C_K__ICPP_CMD_RESPONSE_SIZE_VENDOR_SPECIFIC  (512U)

// chip attestation certificate tag as per icpp_parser.h
#define C_K__ICPP_FIELD_TAG_PUB_KEY_VENDOR_SPECIFIC  0xF9

/* -------------------------------------------------------------------------- */
/* VARIABLES                                                                  */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* FUNCTIONS                                                                  */
/* -------------------------------------------------------------------------- */

#ifdef __cplusplus
}
#endif /* C++ */

#endif // CRYPTOCONFIG_H

/* -------------------------------------------------------------------------- */
/* END OF FILE                                                                */
/* -------------------------------------------------------------------------- */
