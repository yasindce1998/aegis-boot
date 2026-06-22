/** @file
  Device Tree Blob Injection Emulation - Implementation

  Emulates ARM device tree manipulation attacks. Locates the FDT in
  memory, parses its structure, injects a malicious device node with
  attacker-controlled firmware binding, and installs the modified DTB.

  All operations are SIMULATED - no actual device tree is modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "DeviceTreeInject.h"

STATIC DTI_CONTEXT  mDtiContext;

EFI_STATUS
EFIAPI
InitializeDeviceTreeInject (
  OUT DTI_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (DTI_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = DtiStateUninitialized;

  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
LocateDeviceTree (
  IN OUT DTI_CONTEXT  *Context
  )
{
  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "Locating FDT in system memory...\n"));

  if (SIMULATION_MODE) {
    Context->DtbBase = DTI_DTB_BASE_ADDR;

    Context->Header.Magic = FDT_MAGIC;
    Context->Header.TotalSize = DTI_DTB_ORIGINAL_SIZE;
    Context->Header.OffDtStruct = 0x38;
    Context->Header.OffDtStrings = 0x1C000;
    Context->Header.OffMemRsvmap = 0x28;
    Context->Header.Version = FDT_VERSION;
    Context->Header.LastCompVersion = FDT_LAST_COMP_VER;
    Context->Header.BootCpuidPhys = 0;
    Context->Header.SizeDtStrings = 0x2000;
    Context->Header.SizeDtStruct = 0x1BFC8;

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  FDT located at: 0x%016lx [SIMULATED]\n",
            Context->DtbBase));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Magic:          0x%08x (valid)\n",
            Context->Header.Magic));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Total size:     0x%x (%d KB)\n",
            Context->Header.TotalSize, Context->Header.TotalSize / 1024));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Version:        %d (last compat: %d)\n",
            Context->Header.Version, Context->Header.LastCompVersion));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Struct offset:  0x%x  size: 0x%x\n",
            Context->Header.OffDtStruct, Context->Header.SizeDtStruct));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Strings offset: 0x%x  size: 0x%x\n",
            Context->Header.OffDtStrings, Context->Header.SizeDtStrings));
  }

  Context->State = DtiStateDtbLocated;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ParseDeviceTree (
  IN OUT DTI_CONTEXT  *Context
  )
{
  UINT32  Index;

  if (Context->State < DtiStateDtbLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "Parsing device tree structure...\n"));

  if (SIMULATION_MODE) {
    Context->NodeCount = 0;

    // Root node
    AsciiStrCpyS (Context->Nodes[0].Name, DTI_MAX_NAME_LEN, "/");
    Context->Nodes[0].Offset = 0x38;
    Context->Nodes[0].Depth = 0;
    Context->Nodes[0].NumProperties = 4;
    Context->Nodes[0].IsTarget = FALSE;
    Context->NodeCount++;

    // CPU node
    AsciiStrCpyS (Context->Nodes[1].Name, DTI_MAX_NAME_LEN, "cpus");
    Context->Nodes[1].Offset = 0x100;
    Context->Nodes[1].Depth = 1;
    Context->Nodes[1].NumProperties = 2;
    Context->Nodes[1].IsTarget = FALSE;
    Context->NodeCount++;

    // Memory node
    AsciiStrCpyS (Context->Nodes[2].Name, DTI_MAX_NAME_LEN, "memory@80000000");
    Context->Nodes[2].Offset = 0x400;
    Context->Nodes[2].Depth = 1;
    Context->Nodes[2].NumProperties = 2;
    Context->Nodes[2].IsTarget = FALSE;
    Context->NodeCount++;

    // Platform bus (our injection target)
    AsciiStrCpyS (Context->Nodes[3].Name, DTI_MAX_NAME_LEN, "platform-bus@c000000");
    Context->Nodes[3].Offset = 0x2000;
    Context->Nodes[3].Depth = 1;
    Context->Nodes[3].NumProperties = 5;
    Context->Nodes[3].IsTarget = TRUE;
    Context->NodeCount++;

    // GIC (interrupt controller)
    AsciiStrCpyS (Context->Nodes[4].Name, DTI_MAX_NAME_LEN, "interrupt-controller@8000000");
    Context->Nodes[4].Offset = 0x3000;
    Context->Nodes[4].Depth = 1;
    Context->Nodes[4].NumProperties = 6;
    Context->Nodes[4].IsTarget = FALSE;
    Context->NodeCount++;

    // Timer node
    AsciiStrCpyS (Context->Nodes[5].Name, DTI_MAX_NAME_LEN, "timer");
    Context->Nodes[5].Offset = 0x5000;
    Context->Nodes[5].Depth = 1;
    Context->Nodes[5].NumProperties = 3;
    Context->Nodes[5].IsTarget = FALSE;
    Context->NodeCount++;

    // Firmware node (existing)
    AsciiStrCpyS (Context->Nodes[6].Name, DTI_MAX_NAME_LEN, "firmware");
    Context->Nodes[6].Offset = 0x8000;
    Context->Nodes[6].Depth = 1;
    Context->Nodes[6].NumProperties = 1;
    Context->Nodes[6].IsTarget = FALSE;
    Context->NodeCount++;

    // Chosen node
    AsciiStrCpyS (Context->Nodes[7].Name, DTI_MAX_NAME_LEN, "chosen");
    Context->Nodes[7].Offset = 0xA000;
    Context->Nodes[7].Depth = 1;
    Context->Nodes[7].NumProperties = 3;
    Context->Nodes[7].IsTarget = FALSE;
    Context->NodeCount++;

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Parsed %d top-level nodes:\n", Context->NodeCount));
    for (Index = 0; Index < Context->NodeCount; Index++) {
      DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    [%d] /%a  (offset=0x%x, props=%d)%a\n",
              Index, Context->Nodes[Index].Name, Context->Nodes[Index].Offset,
              Context->Nodes[Index].NumProperties,
              Context->Nodes[Index].IsTarget ? " <-- TARGET" : ""));
    }

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Injection target: /%a\n",
            Context->Nodes[3].Name));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    Will inject child node under platform bus\n"));
  }

  Context->State = DtiStateDtbParsed;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
InjectMaliciousNode (
  IN OUT DTI_CONTEXT  *Context
  )
{
  if (Context->State < DtiStateDtbParsed) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "Injecting malicious device node...\n"));

  if (SIMULATION_MODE) {
    AsciiStrCpyS (Context->Payload.NodeName, DTI_MAX_NAME_LEN, "barzakh-dma@e000000");
    AsciiStrCpyS (Context->Payload.Compatible, DTI_MAX_VALUE_LEN,
                  "barzakh,persistence-engine\0arm,primecell");
    AsciiStrCpyS (Context->Payload.FirmwareName, DTI_MAX_NAME_LEN, "barzakh-fw.bin");
    Context->Payload.RegBase = 0x0E000000;
    Context->Payload.RegSize = 0x00010000;
    Context->Payload.InjectedOffset = DTI_INJECT_OFFSET;
    Context->Payload.InjectedSize = 0x120;

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Node name:    %a\n", Context->Payload.NodeName));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Compatible:   %a\n", Context->Payload.Compatible));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Reg:          <0x%08lx 0x%08lx>\n",
            Context->Payload.RegBase, Context->Payload.RegSize));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Firmware:     %a\n", Context->Payload.FirmwareName));

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Injection details:\n"));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    Parent: /%a (offset 0x%x)\n",
            Context->Nodes[3].Name, Context->Nodes[3].Offset));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    Insert at struct offset: 0x%x\n",
            Context->Payload.InjectedOffset));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    Payload size: 0x%x bytes\n",
            Context->Payload.InjectedSize));

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Constructing FDT tokens [SIMULATED]:\n"));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    0x%08x  FDT_BEGIN_NODE\n", FDT_BEGIN_NODE));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    \"%a\\0\" (padded to 4-byte align)\n",
            Context->Payload.NodeName));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    0x%08x  FDT_PROP (compatible)\n", FDT_PROP));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    0x%08x  FDT_PROP (reg)\n", FDT_PROP));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    0x%08x  FDT_PROP (firmware-name)\n", FDT_PROP));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    0x%08x  FDT_PROP (status = \"okay\")\n", FDT_PROP));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "    0x%08x  FDT_END_NODE\n", FDT_END_NODE));

    Context->DtbModified = TRUE;
    Context->NewTotalSize = Context->Header.TotalSize + Context->Payload.InjectedSize;

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  -> Node injected into struct block [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  -> New DTB size: 0x%x (was 0x%x, +%d bytes)\n",
            Context->NewTotalSize, Context->Header.TotalSize, Context->Payload.InjectedSize));
  }

  Context->State = DtiStateNodeInjected;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
InstallModifiedDtb (
  IN OUT DTI_CONTEXT  *Context
  )
{
  if (Context->State < DtiStateNodeInjected) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "Installing modified DTB...\n"));

  if (SIMULATION_MODE) {
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Step 1: Update fdt_header.totalsize = 0x%x [SIMULATED]\n",
            Context->NewTotalSize));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Step 2: Update fdt_header.size_dt_struct += 0x%x [SIMULATED]\n",
            Context->Payload.InjectedSize));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Step 3: Shift strings block forward by 0x%x [SIMULATED]\n",
            Context->Payload.InjectedSize));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Step 4: Fix off_dt_strings += 0x%x [SIMULATED]\n",
            Context->Payload.InjectedSize));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Step 5: Flush cache (DC CIVAC range) [SIMULATED]\n"));

    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  -> Modified DTB installed at 0x%016lx [SIMULATED]\n",
            Context->DtbBase));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  -> Kernel will see injected device at next boot\n"));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  -> Platform driver probe will load: %a\n",
            Context->Payload.FirmwareName));
    DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  -> Persistence: DTB in firmware partition survives reboot\n"));
  }

  Context->State = DtiStateDtbInstalled;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogDeviceTreeInjectStatus (
  IN     DTI_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case DtiStateUninitialized: StateStr = "Uninitialized"; break;
    case DtiStateDtbLocated:    StateStr = "DTB Located"; break;
    case DtiStateDtbParsed:     StateStr = "DTB Parsed"; break;
    case DtiStateNodeInjected:  StateStr = "Node Injected"; break;
    case DtiStateDtbInstalled:  StateStr = "DTB Installed"; break;
    default:                    StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "=== Device Tree Injection Status ===\n"));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  State:         %a\n", StateStr));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  DTB Base:      0x%016lx\n", Context->DtbBase));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Original Size: 0x%x (%d KB)\n",
          Context->Header.TotalSize, Context->Header.TotalSize / 1024));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Modified Size: 0x%x (%d KB)\n",
          Context->NewTotalSize, Context->NewTotalSize / 1024));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Nodes Parsed:  %d\n", Context->NodeCount));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  Injected Node: %a\n", Context->Payload.NodeName));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "  DTB Modified:  %a\n",
          Context->DtbModified ? "YES" : "No"));
  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "====================================\n\n"));
}

EFI_STATUS
EFIAPI
DeviceTreeInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "Module loaded - Device Tree Injection Emulation\n"));

  Status = InitializeDeviceTreeInject (&mDtiContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = LocateDeviceTree (&mDtiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, DTI_DEBUG_PREFIX "DTB location failed: %r\n", Status));
    return Status;
  }

  Status = ParseDeviceTree (&mDtiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, DTI_DEBUG_PREFIX "DTB parsing failed: %r\n", Status));
    return Status;
  }

  Status = InjectMaliciousNode (&mDtiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, DTI_DEBUG_PREFIX "Node injection failed: %r\n", Status));
    return Status;
  }

  Status = InstallModifiedDtb (&mDtiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, DTI_DEBUG_PREFIX "DTB install failed: %r\n", Status));
    return Status;
  }

  LogDeviceTreeInjectStatus (&mDtiContext);

  DEBUG ((DEBUG_INFO, DTI_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}
