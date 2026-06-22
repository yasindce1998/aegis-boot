/** @file
  SEP Mailbox Intercept Emulation - Implementation

  Emulates Apple Secure Enclave Processor (SEP) mailbox communication
  interception. Models the AP<->SEP hardware mailbox FIFO, message parsing,
  endpoint channel mapping, and key request/response hijacking.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  This module serves as a research reference for defensive security teams
  studying Apple SEP communication attack vectors.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SepMailboxIntercept.h"

STATIC SEP_CONTEXT  gSepContext;

/**
  Initialize SEP intercept context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeSepIntercept (
  OUT SEP_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (SEP_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = SepStateUninitialized;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Target: Apple SEP mailbox interception\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Attack vector: AP<->SEP FIFO message snooping\n"));

  return EFI_SUCCESS;
}

/**
  Locate the SEP hardware mailbox in the SoC address map.

  On Apple Silicon, the SEP communicates with the AP via a memory-mapped
  mailbox consisting of inbox (AP->SEP) and outbox (SEP->AP) FIFOs.
  The mailbox is typically at a fixed address in the MMIO region.
**/
EFI_STATUS
EFIAPI
LocateSepMailbox (
  IN OUT SEP_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "--- Phase 1: Locate SEP Mailbox ---\n"));

  //
  // In a real attack, the mailbox address is discovered via:
  // 1. Device tree parsing (sep-mailbox node)
  // 2. Known SoC-specific fixed addresses
  // 3. AOP (Always-On Processor) firmware reverse engineering
  //
  Context->MboxBase   = SEP_MBOX_BASE;
  Context->InboxAddr  = SEP_MBOX_BASE + SEP_INBOX_OFFSET;
  Context->OutboxAddr = SEP_MBOX_BASE + SEP_OUTBOX_OFFSET;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "SEP mailbox base: 0x%lx\n", Context->MboxBase));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  Inbox (AP->SEP):  0x%lx\n", Context->InboxAddr));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  Outbox (SEP->AP): 0x%lx\n", Context->OutboxAddr));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  Status register:  0x%lx\n", SEP_MBOX_BASE + SEP_STATUS_OFFSET));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  Control register: 0x%lx\n", SEP_MBOX_BASE + SEP_CONTROL_OFFSET));

  //
  // Simulate reading FIFO status
  //
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[SIM] Reading FIFO status at 0x%lx\n",
    Context->InboxAddr + SEP_MBOX_FIFO_STATUS));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[SIM] Inbox FIFO: not full (ready for messages)\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[SIM] Outbox FIFO: not empty (responses pending)\n"));

  Context->State = SepStateMailboxLocated;
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "State -> MailboxLocated\n"));

  return EFI_SUCCESS;
}

/**
  Map SEP communication channels (endpoints).

  The SEP exposes multiple logical endpoints over the shared mailbox:
  - Control (EP0): initialization, power management
  - Keystore (EP1): key generation, wrapping, unwrapping
  - Biometric (EP2): Touch ID / Face ID enrollment and matching
  - Secure Credentials (EP3): password/token storage
  - Apple Pay (EP4): payment token generation
**/
EFI_STATUS
EFIAPI
MapSepChannels (
  IN OUT SEP_CONTEXT  *Context
  )
{
  UINT32  Ep;

  if (Context == NULL || Context->State < SepStateMailboxLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "--- Phase 2: Map SEP Channels ---\n"));

  //
  // In reality, endpoints are discovered by observing the control channel
  // initialization sequence. The AP sends EP_OPEN messages, and the SEP
  // responds with endpoint capabilities.
  //
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Enumerating SEP endpoints:\n"));

  for (Ep = 0; Ep < SEP_EP_MAX; Ep++) {
    Context->EndpointMapped[Ep] = TRUE;
    Context->ActiveEndpoints++;
  }

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  EP0 (Control):     MAPPED - init/power management\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  EP1 (Keystore):    MAPPED - AES/EC key operations [TARGET]\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  EP2 (Biometric):   MAPPED - Touch ID/Face ID\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  EP3 (SecureCred):  MAPPED - credential storage\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  EP4 (ApplePay):    MAPPED - payment tokens\n"));

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Total active endpoints: %u\n", Context->ActiveEndpoints));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Primary targets: EP1 (Keystore), EP2 (Biometric)\n"));

  //
  // Simulating the mailbox message format discovery
  //
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Message format: [EP:8][OP:8][TAG:16][LEN:16][RSV:16] + payload\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Header size: %u bytes, max payload: %u bytes\n",
    SEP_MSG_HEADER_SIZE, SEP_MSG_MAX_PAYLOAD));

  Context->State = SepStateChannelMapped;
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "State -> ChannelMapped\n"));

  return EFI_SUCCESS;
}

/**
  Intercept messages on the SEP mailbox FIFO.

  Monitors both inbox (AP->SEP requests) and outbox (SEP->AP responses)
  to capture key material in transit. The attack focuses on:
  1. KEY_UNWRAP responses containing plaintext key material
  2. KEY_LOAD requests revealing key handles and metadata
  3. BIO_MATCH responses for authentication bypass
**/
EFI_STATUS
EFIAPI
InterceptSepMessages (
  IN OUT SEP_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < SepStateChannelMapped) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "--- Phase 3: Intercept SEP Messages ---\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Installing FIFO tap on inbox and outbox...\n"));

  //
  // Simulate intercepting a series of AP<->SEP messages.
  // In a real attack, this would involve:
  // 1. Polling/DMA-snooping the outbox FIFO before the AP reads it
  // 2. Copying messages before they're consumed
  // 3. Identifying key-bearing responses by opcode
  //

  // Message 1: AP requests key load (inbound)
  Idx = Context->InterceptCount;
  Context->Intercepted[Idx].Message.Endpoint   = SEP_EP_KEYSTORE;
  Context->Intercepted[Idx].Message.Opcode     = SEP_OP_KEY_LOAD;
  Context->Intercepted[Idx].Message.Tag        = 0x0001;
  Context->Intercepted[Idx].Message.PayloadLen = 4;
  Context->Intercepted[Idx].Message.Payload[0] = 0x01;  // Key ID = 1
  Context->Intercepted[Idx].IsInbound          = TRUE;
  Context->Intercepted[Idx].ContainsKey        = FALSE;
  Context->InterceptCount++;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[INTERCEPT] AP->SEP: EP1/KEY_LOAD tag=0x0001 keyId=0x01\n"));

  // Message 2: SEP responds with key handle (outbound)
  Idx = Context->InterceptCount;
  Context->Intercepted[Idx].Message.Endpoint   = SEP_EP_KEYSTORE;
  Context->Intercepted[Idx].Message.Opcode     = SEP_OP_RESPONSE;
  Context->Intercepted[Idx].Message.Tag        = 0x0001;
  Context->Intercepted[Idx].Message.PayloadLen = 8;
  Context->Intercepted[Idx].Message.Payload[0] = 0x00;  // Status: success
  Context->Intercepted[Idx].Message.Payload[4] = 0xAA;  // Key handle
  Context->Intercepted[Idx].IsInbound          = FALSE;
  Context->Intercepted[Idx].ContainsKey        = FALSE;
  Context->InterceptCount++;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[INTERCEPT] SEP->AP: EP1/RESPONSE tag=0x0001 handle=0x000000AA\n"));

  // Message 3: AP requests key unwrap (inbound)
  Idx = Context->InterceptCount;
  Context->Intercepted[Idx].Message.Endpoint   = SEP_EP_KEYSTORE;
  Context->Intercepted[Idx].Message.Opcode     = SEP_OP_KEY_UNWRAP;
  Context->Intercepted[Idx].Message.Tag        = 0x0002;
  Context->Intercepted[Idx].Message.PayloadLen = 48;
  Context->Intercepted[Idx].Message.Payload[0] = 0x01;  // Key ID
  Context->Intercepted[Idx].IsInbound          = TRUE;
  Context->Intercepted[Idx].ContainsKey        = FALSE;
  Context->InterceptCount++;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[INTERCEPT] AP->SEP: EP1/KEY_UNWRAP tag=0x0002 wrappedLen=48\n"));

  // Message 4: SEP responds with unwrapped key (outbound) - CRITICAL
  Idx = Context->InterceptCount;
  Context->Intercepted[Idx].Message.Endpoint   = SEP_EP_KEYSTORE;
  Context->Intercepted[Idx].Message.Opcode     = SEP_OP_RESPONSE;
  Context->Intercepted[Idx].Message.Tag        = 0x0002;
  Context->Intercepted[Idx].Message.PayloadLen = 36;
  Context->Intercepted[Idx].Message.Payload[0] = 0x00;  // Status: success
  // Simulated unwrapped 256-bit AES key at offset 4
  Context->Intercepted[Idx].Message.Payload[4]  = 0xDE;
  Context->Intercepted[Idx].Message.Payload[5]  = 0xAD;
  Context->Intercepted[Idx].Message.Payload[6]  = 0xBE;
  Context->Intercepted[Idx].Message.Payload[7]  = 0xEF;
  Context->Intercepted[Idx].Message.Payload[8]  = 0xCA;
  Context->Intercepted[Idx].Message.Payload[9]  = 0xFE;
  Context->Intercepted[Idx].Message.Payload[10] = 0xBA;
  Context->Intercepted[Idx].Message.Payload[11] = 0xBE;
  Context->Intercepted[Idx].IsInbound           = FALSE;
  Context->Intercepted[Idx].ContainsKey         = TRUE;
  Context->InterceptCount++;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[INTERCEPT] SEP->AP: EP1/RESPONSE tag=0x0002 *** KEY MATERIAL ***\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[CRITICAL] Unwrapped AES-256 key detected in FIFO response!\n"));

  // Message 5: Biometric match request (inbound)
  Idx = Context->InterceptCount;
  Context->Intercepted[Idx].Message.Endpoint   = SEP_EP_BIOMETRIC;
  Context->Intercepted[Idx].Message.Opcode     = SEP_OP_BIO_MATCH;
  Context->Intercepted[Idx].Message.Tag        = 0x0003;
  Context->Intercepted[Idx].Message.PayloadLen = 16;
  Context->Intercepted[Idx].IsInbound          = TRUE;
  Context->Intercepted[Idx].ContainsKey        = FALSE;
  Context->InterceptCount++;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[INTERCEPT] AP->SEP: EP2/BIO_MATCH tag=0x0003\n"));

  // Message 6: Biometric match response (outbound)
  Idx = Context->InterceptCount;
  Context->Intercepted[Idx].Message.Endpoint   = SEP_EP_BIOMETRIC;
  Context->Intercepted[Idx].Message.Opcode     = SEP_OP_RESPONSE;
  Context->Intercepted[Idx].Message.Tag        = 0x0003;
  Context->Intercepted[Idx].Message.PayloadLen = 4;
  Context->Intercepted[Idx].Message.Payload[0] = 0x01;  // Match: success
  Context->Intercepted[Idx].IsInbound          = FALSE;
  Context->Intercepted[Idx].ContainsKey        = FALSE;
  Context->InterceptCount++;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[INTERCEPT] SEP->AP: EP2/RESPONSE tag=0x0003 match=TRUE\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  Note: biometric bypass possible by replaying this response\n"));

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Total messages intercepted: %u\n", Context->InterceptCount));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Messages containing key material: 1\n"));

  Context->State = SepStateMessageIntercepted;
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "State -> MessageIntercepted\n"));

  return EFI_SUCCESS;
}

/**
  Extract and exfiltrate key material from intercepted messages.

  Scans intercepted FIFO messages for key-bearing responses and
  extracts the plaintext cryptographic material. In a real attack,
  this would be exfiltrated via DMA, side-channel, or stored for
  later retrieval.
**/
EFI_STATUS
EFIAPI
ExfiltrateSepKeys (
  IN OUT SEP_CONTEXT  *Context
  )
{
  UINT32  Idx;
  UINT32  KeyIdx;
  UINT32  ByteIdx;

  if (Context == NULL || Context->State < SepStateMessageIntercepted) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "--- Phase 4: Exfiltrate Key Material ---\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Scanning %u intercepted messages for key material...\n",
    Context->InterceptCount));

  KeyIdx = 0;

  for (Idx = 0; Idx < Context->InterceptCount && KeyIdx < SEP_MAX_KEYS; Idx++) {
    if (!Context->Intercepted[Idx].ContainsKey) {
      continue;
    }

    //
    // Extract key from response payload
    // Key data starts at payload offset 4 (after status field)
    //
    Context->Keys[KeyIdx].KeyId  = Context->Intercepted[Idx].Message.Payload[0];
    Context->Keys[KeyIdx].KeyLen = SEP_SIM_KEY_SIZE;

    for (ByteIdx = 0; ByteIdx < SEP_SIM_KEY_SIZE; ByteIdx++) {
      if (ByteIdx + 4 < Context->Intercepted[Idx].Message.PayloadLen) {
        Context->Keys[KeyIdx].KeyData[ByteIdx] =
          Context->Intercepted[Idx].Message.Payload[ByteIdx + 4];
      } else {
        Context->Keys[KeyIdx].KeyData[ByteIdx] = 0x00;
      }
    }

    Context->Keys[KeyIdx].Exfiltrated = TRUE;
    KeyIdx++;
  }

  Context->KeyCount = KeyIdx;

  if (KeyIdx > 0) {
    Context->KeysExfiltrated = TRUE;

    DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Extracted %u key(s) from intercepted messages:\n", KeyIdx));
    for (Idx = 0; Idx < KeyIdx; Idx++) {
      DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  Key[%u]: ID=0x%02x Len=%u bytes\n",
        Idx, Context->Keys[Idx].KeyId, Context->Keys[Idx].KeyLen));
      DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "    First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
        Context->Keys[Idx].KeyData[0], Context->Keys[Idx].KeyData[1],
        Context->Keys[Idx].KeyData[2], Context->Keys[Idx].KeyData[3],
        Context->Keys[Idx].KeyData[4], Context->Keys[Idx].KeyData[5],
        Context->Keys[Idx].KeyData[6], Context->Keys[Idx].KeyData[7]));
    }

    //
    // In a real attack, exfiltration methods include:
    // 1. DMA to external device
    // 2. Store in non-volatile memory for later retrieval
    // 3. Encode in covert timing channel
    // 4. Write to shared memory accessible from non-secure world
    //
    DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[SIM] Key exfiltration vector: shared memory write\n"));
    DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "[SIM] Would write to non-secure DRAM at 0x%lx\n",
      (UINT64)0x880000000ULL));
  } else {
    DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "No key material found in intercepted messages\n"));
  }

  Context->State = SepStateKeysExfiltrated;
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "State -> KeysExfiltrated\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the SEP mailbox interception emulation.
**/
VOID
EFIAPI
LogSepInterceptStatus (
  IN SEP_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "  SEP Mailbox Intercept - Final Status\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case SepStateUninitialized:
      StateStr = "Uninitialized";
      break;
    case SepStateMailboxLocated:
      StateStr = "MailboxLocated";
      break;
    case SepStateChannelMapped:
      StateStr = "ChannelMapped";
      break;
    case SepStateMessageIntercepted:
      StateStr = "MessageIntercepted";
      break;
    case SepStateKeysExfiltrated:
      StateStr = "KeysExfiltrated";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Mailbox base:       0x%lx\n", Context->MboxBase));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Active endpoints:   %u / %u\n",
    Context->ActiveEndpoints, (UINT32)SEP_EP_MAX));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Messages captured:  %u\n", Context->InterceptCount));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Keys exfiltrated:   %u\n", Context->KeyCount));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Exfil successful:   %a\n",
    Context->KeysExfiltrated ? "YES" : "NO"));

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "1. SEP mailbox is memory-mapped with strict IOMMU isolation\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "2. Messages are encrypted end-to-end (SEP<->AP session keys)\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "3. Key material never leaves SEP in plaintext on production\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "4. FIFO access requires EL2/EL3 privilege level\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "5. Hardware tamper detection zeros SEP state on intrusion\n"));
}

/**
  Entry point for the SEP Mailbox Intercept emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
SepMailboxInterceptEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "=== Apple SEP Mailbox Intercept Emulation ===\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Module: SepMailboxIntercept v1.0\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Purpose: Model AP<->SEP communication hijacking\n"));
  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  Status = InitializeSepIntercept (&gSepContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SEP_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateSepMailbox (&gSepContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SEP_DEBUG_PREFIX "Failed to locate mailbox: %r\n", Status));
    goto Done;
  }

  Status = MapSepChannels (&gSepContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SEP_DEBUG_PREFIX "Failed to map channels: %r\n", Status));
    goto Done;
  }

  Status = InterceptSepMessages (&gSepContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SEP_DEBUG_PREFIX "Failed to intercept messages: %r\n", Status));
    goto Done;
  }

  Status = ExfiltrateSepKeys (&gSepContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SEP_DEBUG_PREFIX "Failed to exfiltrate keys: %r\n", Status));
    goto Done;
  }

Done:
  LogSepInterceptStatus (&gSepContext);

  DEBUG ((DEBUG_INFO, SEP_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
