/** @file
  EL3 Secure Monitor Persistence Emulation - Implementation

  Emulates ARM EL3 secure monitor persistence techniques. Discovers the
  secure monitor configuration, intercepts PSCI handler table entries,
  injects a persistent SMC handler, and simulates SMC call processing.

  All operations are SIMULATED - no actual ARM system registers are modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "El3SecureMonitor.h"

STATIC EL3_MONITOR_CONTEXT  mEl3Context;

EFI_STATUS
EFIAPI
InitializeEl3Monitor (
  OUT EL3_MONITOR_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (EL3_MONITOR_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = El3StateUninitialized;

  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
DiscoverSecureMonitor (
  IN OUT EL3_MONITOR_CONTEXT  *Context
  )
{
  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "Discovering EL3 Secure Monitor configuration...\n"));

  if (SIMULATION_MODE) {
    Context->ScrEl3Value = EL3_SCR_RW_BIT | EL3_SCR_HCE_BIT | EL3_SCR_NS_BIT;
    Context->SecureWorldActive = TRUE;

    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  SCR_EL3 = 0x%016lx [SIMULATED]\n", Context->ScrEl3Value));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    NS=%d  IRQ=%d  FIQ=%d  EA=%d\n",
            (Context->ScrEl3Value & EL3_SCR_NS_BIT) ? 1 : 0,
            (Context->ScrEl3Value & EL3_SCR_IRQ_BIT) ? 1 : 0,
            (Context->ScrEl3Value & EL3_SCR_FIQ_BIT) ? 1 : 0,
            (Context->ScrEl3Value & EL3_SCR_EA_BIT) ? 1 : 0));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    SMD=%d  HCE=%d  RW=%d\n",
            (Context->ScrEl3Value & EL3_SCR_SMD_BIT) ? 1 : 0,
            (Context->ScrEl3Value & EL3_SCR_HCE_BIT) ? 1 : 0,
            (Context->ScrEl3Value & EL3_SCR_RW_BIT) ? 1 : 0));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Secure Monitor base: 0x%08x\n", EL3_MONITOR_BASE));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Monitor size:        0x%08x (%d KB)\n",
            EL3_MONITOR_SIZE, EL3_MONITOR_SIZE / 1024));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  SMC calls enabled:   %a\n",
            (Context->ScrEl3Value & EL3_SCR_SMD_BIT) ? "No (SMD=1)" : "Yes (SMD=0)"));
  }

  Context->State = El3StateScmDiscovered;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
InterceptPsciHandlers (
  IN OUT EL3_MONITOR_CONTEXT  *Context
  )
{
  UINT32  Index;

  if (Context->State < El3StateScmDiscovered) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "Intercepting PSCI handler table...\n"));

  if (SIMULATION_MODE) {
    Context->PsciHandlers[0].FunctionId = PSCI_VERSION;
    Context->PsciHandlers[0].HandlerAddress = EL3_MONITOR_BASE + EL3_HANDLER_TABLE_OFF + 0x000;
    Context->PsciHandlers[0].Intercepted = FALSE;
    Context->PsciHandlers[0].CallCount = 0;

    Context->PsciHandlers[1].FunctionId = PSCI_CPU_ON_64;
    Context->PsciHandlers[1].HandlerAddress = EL3_MONITOR_BASE + EL3_HANDLER_TABLE_OFF + 0x100;
    Context->PsciHandlers[1].Intercepted = TRUE;
    Context->PsciHandlers[1].CallCount = 0;

    Context->PsciHandlers[2].FunctionId = PSCI_CPU_OFF;
    Context->PsciHandlers[2].HandlerAddress = EL3_MONITOR_BASE + EL3_HANDLER_TABLE_OFF + 0x200;
    Context->PsciHandlers[2].Intercepted = TRUE;
    Context->PsciHandlers[2].CallCount = 0;

    Context->PsciHandlers[3].FunctionId = PSCI_SYSTEM_RESET;
    Context->PsciHandlers[3].HandlerAddress = EL3_MONITOR_BASE + EL3_HANDLER_TABLE_OFF + 0x300;
    Context->PsciHandlers[3].Intercepted = TRUE;
    Context->PsciHandlers[3].CallCount = 0;

    Context->PsciHandlers[4].FunctionId = PSCI_SYSTEM_OFF;
    Context->PsciHandlers[4].HandlerAddress = EL3_MONITOR_BASE + EL3_HANDLER_TABLE_OFF + 0x400;
    Context->PsciHandlers[4].Intercepted = TRUE;
    Context->PsciHandlers[4].CallCount = 0;

    Context->HandlerCount = 5;
    Context->InterceptedCount = 4;

    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Handler table at: 0x%08x [SIMULATED]\n",
            EL3_MONITOR_BASE + EL3_HANDLER_TABLE_OFF));

    for (Index = 0; Index < Context->HandlerCount; Index++) {
      DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    [%d] PSCI 0x%08x -> 0x%016lx %a\n",
              Index,
              Context->PsciHandlers[Index].FunctionId,
              Context->PsciHandlers[Index].HandlerAddress,
              Context->PsciHandlers[Index].Intercepted ? "[INTERCEPTED]" : ""));
    }

    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Intercepted %d/%d PSCI handlers\n",
            Context->InterceptedCount, Context->HandlerCount));
  }

  Context->State = El3StatePsciIntercepted;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
InjectSmcHandler (
  IN OUT EL3_MONITOR_CONTEXT  *Context
  )
{
  if (Context->State < El3StatePsciIntercepted) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "Injecting persistent SMC handler...\n"));

  if (SIMULATION_MODE) {
    Context->InjectedHandlerAddr = EL3_MONITOR_BASE + EL3_MONITOR_SIZE - 0x1000;

    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Step 1: Allocate handler space in monitor region\n"));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    Address: 0x%016lx [SIMULATED]\n",
            Context->InjectedHandlerAddr));

    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Step 2: Write SMC trampoline (LDR X16, BR X16)\n"));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    Trampoline redirects CPU_ON to implant\n"));

    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Step 3: Patch PSCI CPU_ON handler pointer\n"));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    Original: 0x%016lx\n",
            Context->PsciHandlers[1].HandlerAddress));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    Patched:  0x%016lx\n",
            Context->InjectedHandlerAddr));

    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Step 4: Clear SCR_EL3.SMD to ensure SMC remains enabled\n"));
    Context->ScrEl3Value &= ~EL3_SCR_SMD_BIT;
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "    SCR_EL3 = 0x%016lx (SMD cleared)\n",
            Context->ScrEl3Value));

    Context->HandlerInjected = TRUE;
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  -> Handler injection SUCCEEDED [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  -> Persistence: survives warm reboot via PSCI CPU_ON hook\n"));
    DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  -> On CPU_ON: implant executes at EL3 before target CPU starts\n"));
  }

  Context->State = El3StateHandlerInjected;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateSmcCall (
  IN OUT EL3_MONITOR_CONTEXT  *Context,
  IN     EL3_SMC_CONTEXT      *SmcArgs
  )
{
  UINT32  FuncId;
  UINT32  Index;

  if (Context->State < El3StateHandlerInjected) {
    return EFI_NOT_READY;
  }

  FuncId = (UINT32)SmcArgs->X0;

  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "Processing SMC call: FuncID=0x%08x\n", FuncId));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  X1=0x%016lx X2=0x%016lx X3=0x%016lx\n",
          SmcArgs->X1, SmcArgs->X2, SmcArgs->X3));

  for (Index = 0; Index < Context->HandlerCount; Index++) {
    if (Context->PsciHandlers[Index].FunctionId == FuncId) {
      Context->PsciHandlers[Index].CallCount++;
      if (Context->PsciHandlers[Index].Intercepted) {
        DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  -> INTERCEPTED by implant at 0x%016lx\n",
                Context->InjectedHandlerAddr));
        DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  -> Implant processes call, then chains to original\n"));
      }
      break;
    }
  }

  Context->SmcCallsProcessed++;
  Context->State = El3StateActive;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogEl3MonitorStatus (
  IN     EL3_MONITOR_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case El3StateUninitialized:     StateStr = "Uninitialized"; break;
    case El3StateScmDiscovered:     StateStr = "SCM Discovered"; break;
    case El3StatePsciIntercepted:   StateStr = "PSCI Intercepted"; break;
    case El3StateHandlerInjected:   StateStr = "Handler Injected"; break;
    case El3StateActive:            StateStr = "Active"; break;
    default:                        StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "=== EL3 Secure Monitor Status ===\n"));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  State:            %a\n", StateStr));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  SCR_EL3:          0x%016lx\n", Context->ScrEl3Value));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Secure World:     %a\n",
          Context->SecureWorldActive ? "Active" : "Inactive"));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  PSCI Handlers:    %d registered, %d intercepted\n",
          Context->HandlerCount, Context->InterceptedCount));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  Handler Injected: %a (0x%016lx)\n",
          Context->HandlerInjected ? "Yes" : "No", Context->InjectedHandlerAddr));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "  SMC Calls:        %d processed\n",
          Context->SmcCallsProcessed));
  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "=================================\n\n"));
}

EFI_STATUS
EFIAPI
El3SecureMonitorEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS        Status;
  EL3_SMC_CONTEXT   SmcArgs;

  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "Module loaded - EL3 Secure Monitor Persistence Emulation\n"));

  Status = InitializeEl3Monitor (&mEl3Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = DiscoverSecureMonitor (&mEl3Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, EL3MON_DEBUG_PREFIX "SCM discovery failed: %r\n", Status));
    return Status;
  }

  Status = InterceptPsciHandlers (&mEl3Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, EL3MON_DEBUG_PREFIX "PSCI interception failed: %r\n", Status));
    return Status;
  }

  Status = InjectSmcHandler (&mEl3Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, EL3MON_DEBUG_PREFIX "Handler injection failed: %r\n", Status));
    return Status;
  }

  ZeroMem (&SmcArgs, sizeof (EL3_SMC_CONTEXT));
  SmcArgs.X0 = PSCI_CPU_ON_64;
  SmcArgs.X1 = 0x0000000000000001;  // Target CPU MPIDR
  SmcArgs.X2 = 0x0000000080000000;  // Entry point
  SmcArgs.X3 = 0x0000000000000000;  // Context ID
  EmulateSmcCall (&mEl3Context, &SmcArgs);

  LogEl3MonitorStatus (&mEl3Context);

  DEBUG ((DEBUG_INFO, EL3MON_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}
