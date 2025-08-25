# Readme for KTA
# This package contains
- doc --> KTA and SAL documentation
- kta_lib --> Source code for KTA, SAL and Communication stack
- release_notes.md
- README.md

# More information about package
- KTA source code available in folder kta_lib/SOURCE/kta
- PSA based SAL implementation for reference available at kta_lib/SOURCE/salapi/*.c
- kta_lib/COMMSTACK supports both coap and http comminication protocols
    - coap SAL (k_sal_socket.c k_sal_random.c, k_sal_os.c and k_sal_log.c) implementation available for reference based on mbedcoap.
    - http k_sal_com.c implementation available for reference based on mbed.
- kta_lib/ktaFieldMgntHook.c a wrapper which calls KTA API and to communicate with keySTREAM.
- kta_lib/SOURCE/include/ktaConfig.h to update/configure KTA configuration.


# Integration
## Must implement per MCU/platform for integration
- Implement/Update communication stack SAL for COAP or HTTP.
- Implement/Update SAL for KTA as per PSA available on device.

## keySTREAM server side setup
- Create account in keySTREAM
- Create Fleet profile in keySTREAM
- Claim device using attestation token template.

## KTA integration with App
- Update MACRO "C_KTA_APP__DEVICE_PUBLIC_UID" in ktaConfig.h with Fleet profile name created in keySTREAM
- Once communication stack is up on the device, Call ktaKeyStreamInit() and ktaKeyStreamFieldMgmt()
- ktaKeyStreamFieldMgmt() API start communication between KTA and keySTREAM to onboard device on keySTREAM
- Upon successful onboarding, keySTREAM provision leaf certificate and CA certificates to device.
