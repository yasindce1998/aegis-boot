/** @file
  TrustZone Address Space Controller Manipulation - Implementation

  Emulates TZC-400 region repartitioning to break TrustZone isolation.
  Locates the TZASC controller, maps existing regions, modifies secure
  region attributes to grant non-secure access, and verifies the breach.

  All operations are SIMULATED - no actual TZASC registers are modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "TzascManipulation.h"

STATIC TZASC_CONTEXT  mTzascContext;

EFI_STATUS
EFIAPI
InitializeTzasc (
  OUT TZASC_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (TZASC_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = TzascStateUninitialized;

  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
LocateTzascController (
  IN OUT TZASC_CONTEXT  *Context
  )
{
  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "Locating TZC-400 controller...\n"));

  if (SIMULATION_MODE) {
    Context->TzascBase = TZC400_BASE_ADDRESS;
    Context->NumRegions = TZC_MAX_REGIONS;
    Context->NumFilters = 2;

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  TZC-400 base:    0x%08lx [SIMULATED]\n",
            Context->TzascBase));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  BUILD_CONFIG:    regions=%d, filters=%d\n",
            Context->NumRegions, Context->NumFilters));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  GATE_KEEPER:     0x%08x (all filters open)\n", 0x0F));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  ACTION:          0x%08x (INT+ERR on violation)\n", 0x03));
  }

  Context->State = TzascStateTzascLocated;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
MapTzascRegions (
  IN OUT TZASC_CONTEXT  *Context
  )
{
  UINT32  Index;

  if (Context->State < TzascStateTzascLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "Mapping TZASC memory regions...\n"));

  if (SIMULATION_MODE) {
    // Region 0: Full DRAM (default non-secure)
    Context->Regions[0].BaseLow = TZASC_DRAM_BASE;
    Context->Regions[0].BaseHigh = 0;
    Context->Regions[0].TopLow = 0xFFFFFFFF;
    Context->Regions[0].TopHigh = 0;
    Context->Regions[0].Attributes = TZC_ATTR_S_RD_EN | TZC_ATTR_S_WR_EN | TZC_ATTR_FILTER_EN(0);
    Context->Regions[0].IdAccess = TZC_NSAID_ALL_RW;
    Context->Regions[0].IsSecure = FALSE;

    // Region 1: Secure world memory (TEE/OP-TEE)
    Context->Regions[1].BaseLow = TZASC_SECURE_BASE;
    Context->Regions[1].BaseHigh = 0;
    Context->Regions[1].TopLow = TZASC_SECURE_BASE + TZASC_SECURE_SIZE - 1;
    Context->Regions[1].TopHigh = 0;
    Context->Regions[1].Attributes = TZC_ATTR_S_RD_EN | TZC_ATTR_S_WR_EN | TZC_ATTR_FILTER_EN(0);
    Context->Regions[1].IdAccess = TZC_NSAID_NONE;
    Context->Regions[1].IsSecure = TRUE;

    // Region 2: Secure key storage
    Context->Regions[2].BaseLow = TZASC_SECURE_BASE + TZASC_SECURE_SIZE;
    Context->Regions[2].BaseHigh = 0;
    Context->Regions[2].TopLow = TZASC_SECURE_BASE + TZASC_SECURE_SIZE + 0x00100000 - 1;
    Context->Regions[2].TopHigh = 0;
    Context->Regions[2].Attributes = TZC_ATTR_S_RD_EN | TZC_ATTR_S_WR_EN | TZC_ATTR_FILTER_EN(0);
    Context->Regions[2].IdAccess = TZC_NSAID_NONE;
    Context->Regions[2].IsSecure = TRUE;

    Context->SecureRegionIndex = 1;

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Region map:\n"));
    for (Index = 0; Index < 3; Index++) {
      DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    [%d] 0x%08lx - 0x%08lx  %a  NSAID=0x%05x\n",
              Index,
              Context->Regions[Index].BaseLow,
              Context->Regions[Index].TopLow,
              Context->Regions[Index].IsSecure ? "SECURE" : "NS    ",
              Context->Regions[Index].IdAccess));
    }

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Target: Region %d (Secure TEE memory)\n",
            Context->SecureRegionIndex));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    Base: 0x%08lx  Size: %d MB\n",
            TZASC_SECURE_BASE, TZASC_SECURE_SIZE / (1024 * 1024)));
  }

  Context->State = TzascStateRegionsMapped;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ModifySecureRegion (
  IN OUT TZASC_CONTEXT  *Context
  )
{
  TZASC_REGION_INFO  *Target;

  if (Context->State < TzascStateRegionsMapped) {
    return EFI_NOT_READY;
  }

  Target = &Context->Regions[Context->SecureRegionIndex];

  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "Modifying secure region attributes...\n"));

  if (SIMULATION_MODE) {
    Context->OriginalAttributes = Target->Attributes;
    Context->OriginalIdAccess = Target->IdAccess;

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Original REGION_ATTRIBUTES[%d]: 0x%08x\n",
            Context->SecureRegionIndex, Target->Attributes));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Original REGION_ID_ACCESS[%d]:  0x%08x (no NS access)\n",
            Context->SecureRegionIndex, Target->IdAccess));

    // Grant non-secure read+write access
    Context->ModifiedIdAccess = TZC_NSAID_ALL_RW;
    Context->ModifiedAttributes = Target->Attributes;
    Target->IdAccess = Context->ModifiedIdAccess;

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Step 1: Write REGION_ID_ACCESS[%d] = 0x%08x [SIMULATED]\n",
            Context->SecureRegionIndex, Context->ModifiedIdAccess));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    All NSAID masters now have R/W access\n"));

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Step 2: Flush TZC speculation buffer [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    Write SPECULATION_CTRL = 0x03 (disable speculation)\n"));

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Step 3: Clear any pending INT_STATUS [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    Write INT_CLEAR = 0x0F\n"));

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  -> Region %d is now accessible from Non-Secure world\n",
            Context->SecureRegionIndex));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  -> TrustZone isolation BROKEN for 0x%08lx - 0x%08lx\n",
            Target->BaseLow, Target->TopLow));
  }

  Context->State = TzascStateRegionModified;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
VerifyNonSecureAccess (
  IN OUT TZASC_CONTEXT  *Context
  )
{
  TZASC_REGION_INFO  *Target;

  if (Context->State < TzascStateRegionModified) {
    return EFI_NOT_READY;
  }

  Target = &Context->Regions[Context->SecureRegionIndex];

  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "Verifying non-secure access to secure region...\n"));

  if (SIMULATION_MODE) {
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Attempting NS read from 0x%08lx [SIMULATED]\n",
            Target->BaseLow));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    Result: SUCCESS (no abort, data returned)\n"));

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Attempting NS write to 0x%08lx [SIMULATED]\n",
            Target->BaseLow + 0x100));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    Result: SUCCESS (write committed)\n"));

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Checking INT_STATUS for violations [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "    INT_STATUS = 0x00 (no violations triggered)\n"));

    Context->IsolationBroken = TRUE;

    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  -> Non-Secure access CONFIRMED [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  -> Attack impact: TEE secrets (keys, biometrics) exposed\n"));
    DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  -> Persistence: TZASC config survives until next cold boot\n"));
  }

  Context->State = TzascStateAccessGranted;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogTzascStatus (
  IN     TZASC_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case TzascStateUninitialized:  StateStr = "Uninitialized"; break;
    case TzascStateTzascLocated:   StateStr = "TZASC Located"; break;
    case TzascStateRegionsMapped:  StateStr = "Regions Mapped"; break;
    case TzascStateRegionModified: StateStr = "Region Modified"; break;
    case TzascStateAccessGranted:  StateStr = "Access Granted"; break;
    default:                       StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "=== TZASC Manipulation Status ===\n"));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  State:            %a\n", StateStr));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Controller:       0x%08lx\n", Context->TzascBase));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Target Region:    %d (0x%08lx - 0x%08lx)\n",
          Context->SecureRegionIndex,
          Context->Regions[Context->SecureRegionIndex].BaseLow,
          Context->Regions[Context->SecureRegionIndex].TopLow));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Original Access:  0x%08x\n", Context->OriginalIdAccess));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Modified Access:  0x%08x\n", Context->ModifiedIdAccess));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "  Isolation Broken: %a\n",
          Context->IsolationBroken ? "YES" : "No"));
  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "=================================\n\n"));
}

EFI_STATUS
EFIAPI
TzascManipulationEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "Module loaded - TZASC Manipulation Emulation\n"));

  Status = InitializeTzasc (&mTzascContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = LocateTzascController (&mTzascContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, TZASC_DEBUG_PREFIX "Controller location failed: %r\n", Status));
    return Status;
  }

  Status = MapTzascRegions (&mTzascContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, TZASC_DEBUG_PREFIX "Region mapping failed: %r\n", Status));
    return Status;
  }

  Status = ModifySecureRegion (&mTzascContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, TZASC_DEBUG_PREFIX "Region modification failed: %r\n", Status));
    return Status;
  }

  Status = VerifyNonSecureAccess (&mTzascContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, TZASC_DEBUG_PREFIX "Access verification: %r\n", Status));
  }

  LogTzascStatus (&mTzascContext);

  DEBUG ((DEBUG_INFO, TZASC_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}
