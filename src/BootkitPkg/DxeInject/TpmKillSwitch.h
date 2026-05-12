/** @file
  TPM-Based Kill-Switch Module

  Implements enhanced kill-switches using TPM Endorsement Key validation
  and monotonic counter expiry for improved security and safety.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __TPM_KILL_SWITCH_H__
#define __TPM_KILL_SWITCH_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Protocol/Tcg2Protocol.h>

//
// TPM Kill-Switch Configuration
//
#define TPM_EXPIRY_COUNTER      1000000  // Monotonic counter expiry value
#define TPM_EK_SIZE             256      // TPM EK public key size

//
// TPM Kill-Switch Result
//
typedef enum {
  TpmKillSwitchSuccess = 0,
  TpmKillSwitchNoTpm,
  TpmKillSwitchEkMismatch,
  TpmKillSwitchCounterExpired,
  TpmKillSwitchError
} TPM_KILL_SWITCH_RESULT;

//
// Expected TPM EK (for authorized systems only)
//
typedef struct {
  UINT8     PublicKey[TPM_EK_SIZE];
  UINT32    KeySize;
  BOOLEAN   Initialized;
} TPM_EXPECTED_EK;

/**
  Validate TPM Endorsement Key against expected value.

  @param[in]  ExpectedEk  Expected EK structure.

  @retval TPM_KILL_SWITCH_RESULT  Validation result.
**/
TPM_KILL_SWITCH_RESULT
EFIAPI
ValidateTpmEndorsementKey (
  IN TPM_EXPECTED_EK  *ExpectedEk
  );

/**
  Check TPM monotonic counter for expiry.

  @param[in]  ExpiryValue  Counter value that triggers expiry.

  @retval TPM_KILL_SWITCH_RESULT  Check result.
**/
TPM_KILL_SWITCH_RESULT
EFIAPI
CheckTpmMonotonicCounter (
  IN UINT64  ExpiryValue
  );

/**
  Validate signed timestamp from remote server.

  @param[in]  Timestamp  Unix timestamp to validate.
  @param[in]  Signature  Signature over timestamp.
  @param[in]  SigSize    Signature size.

  @retval TPM_KILL_SWITCH_RESULT  Validation result.
**/
TPM_KILL_SWITCH_RESULT
EFIAPI
ValidateSignedTimestamp (
  IN UINT64  Timestamp,
  IN UINT8   *Signature,
  IN UINT32  SigSize
  );

/**
  Initialize TPM kill-switch subsystem.

  @retval EFI_SUCCESS  Initialization successful.
  @retval Other        Error occurred.
**/
EFI_STATUS
EFIAPI
InitializeTpmKillSwitch (
  VOID
  );

/**
  Log TPM kill-switch status.

  @param[in]  Result  Kill-switch validation result.
**/
VOID
EFIAPI
LogTpmKillSwitchStatus (
  IN TPM_KILL_SWITCH_RESULT  Result
  );

#endif // __TPM_KILL_SWITCH_H__

// Made with Bob
