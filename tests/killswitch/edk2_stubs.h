/** @file
  Minimal EDK2 type and function stubs for host-side unit testing.

  Provides just enough of the UEFI type system and library functions
  to compile KillSwitch.c with gcc on a host OS. Protocol-dependent
  functions will compile but must not be called (gBS/gRT are NULL).
**/

#ifndef __EDK2_STUBS_H__
#define __EDK2_STUBS_H__

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* ===== Suppress real EDK2 header includes ===== */
#define __KILL_SWITCH_H__
#define __BASE_H__
#define __UEFI_H__

/* ===== Basic UEFI types ===== */
typedef uint8_t   BOOLEAN;
typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef size_t    UINTN;
typedef int64_t   INTN;
typedef int32_t   INT32;
typedef char      CHAR8;
typedef char      CHAR16;
typedef void      VOID;

#define TRUE   1
#define FALSE  0
#define NULL_PTR  ((VOID *)0)

/* Parameter decorators */
#define IN
#define OUT
#define STATIC     static
#define CONST      const
#define OPTIONAL
#define EFIAPI

/* ===== EFI_STATUS ===== */
typedef UINTN  EFI_STATUS;
typedef UINTN  RETURN_STATUS;

#define EFI_SUCCESS              ((EFI_STATUS)0)
#define EFI_INVALID_PARAMETER    ((EFI_STATUS)(0x8000000000000002ULL))
#define EFI_NOT_FOUND            ((EFI_STATUS)(0x800000000000000EULL))
#define EFI_BUFFER_TOO_SMALL     ((EFI_STATUS)(0x8000000000000005ULL))
#define EFI_ABORTED              ((EFI_STATUS)(0x8000000000000015ULL))

#define EFI_ERROR(Status)  ((INTN)(Status) < 0)

/* ===== DEBUG macro — no-op ===== */
#define DEBUG_INFO   0x00000040
#define DEBUG_WARN   0x00000002
#define DEBUG_ERROR  0x80000000
#define DEBUG(Expression)  do {} while (0)

/* ===== EFI_GUID ===== */
typedef struct {
  UINT32  Data1;
  UINT16  Data2;
  UINT16  Data3;
  UINT8   Data4[8];
} EFI_GUID;

/* ===== EFI_TIME (for ValidateExpiry) ===== */
typedef struct {
  UINT16  Year;
  UINT8   Month;
  UINT8   Day;
  UINT8   Hour;
  UINT8   Minute;
  UINT8   Second;
  UINT8   Pad1;
  UINT32  Nanosecond;
  INT32   TimeZone;
  UINT8   Daylight;
  UINT8   Pad2;
} EFI_TIME;

/* ===== SMBIOS types (for ValidateUuid) ===== */
typedef UINT16 EFI_SMBIOS_HANDLE;
typedef UINT8  EFI_SMBIOS_TYPE;

#define SMBIOS_HANDLE_PI_RESERVED  0xFFFE
#define SMBIOS_TYPE_SYSTEM_INFORMATION  1

typedef struct {
  UINT8   Type;
  UINT8   Length;
  UINT16  Handle;
} SMBIOS_STRUCTURE;

typedef struct {
  UINT32  TimeLow;
  UINT16  TimeMid;
  UINT16  TimeHighAndVersion;
  UINT8   ClockSeqHighAndReserved;
  UINT8   ClockSeqLow;
  UINT8   Node[6];
} SMBIOS_UUID;

typedef struct {
  SMBIOS_STRUCTURE  Hdr;
  UINT8             Manufacturer;
  UINT8             ProductName;
  UINT8             Version;
  UINT8             SerialNumber;
  SMBIOS_UUID       Uuid;
} SMBIOS_TABLE_TYPE1;

typedef struct _EFI_SMBIOS_PROTOCOL EFI_SMBIOS_PROTOCOL;

typedef EFI_STATUS (*EFI_SMBIOS_GET_NEXT)(
  IN     EFI_SMBIOS_PROTOCOL  *This,
  IN OUT EFI_SMBIOS_HANDLE    *SmbiosHandle,
  IN     EFI_SMBIOS_TYPE      *Type,
  OUT    SMBIOS_STRUCTURE     **Record,
  OUT    EFI_SMBIOS_HANDLE    *ProducerHandle
);

struct _EFI_SMBIOS_PROTOCOL {
  EFI_SMBIOS_GET_NEXT  GetNext;
};

/* ===== TCG2 Protocol (for ValidateTpmEk) ===== */
typedef struct {
  UINT8  Dummy;
} EFI_TCG2_PROTOCOL;

/* ===== Boot/Runtime Services (NULL — protocol functions must not be called) ===== */
typedef struct {
  EFI_STATUS (*LocateProtocol)(EFI_GUID *, VOID *, VOID **);
} EFI_BOOT_SERVICES;

typedef struct {
  EFI_STATUS (*GetTime)(EFI_TIME *, VOID *);
} EFI_RUNTIME_SERVICES;

static EFI_BOOT_SERVICES    *gBS = NULL;
static EFI_RUNTIME_SERVICES *gRT = NULL;

/* Protocol GUIDs (unused in tests but needed for compilation) */
static EFI_GUID gEfiSmbiosProtocolGuid = {0, 0, 0, {0}};
static EFI_GUID gEfiTcg2ProtocolGuid   = {0, 0, 0, {0}};

/* ===== KILL_SWITCH_RESULT enum ===== */
typedef enum {
  KillSwitchSuccess = 0,
  KillSwitchUuidMismatch,
  KillSwitchTpmMismatch,
  KillSwitchExpired,
  KillSwitchError
} KILL_SWITCH_RESULT;

/* ===== EDK2 BaseLib string functions ===== */
static inline UINTN AsciiStrLen(const CHAR8 *String) {
  return (UINTN)strlen(String);
}

static inline UINTN AsciiStrDecimalToUintn(const CHAR8 *String) {
  return (UINTN)strtoul(String, NULL, 10);
}

static inline UINTN AsciiStrHexToUintn(const CHAR8 *String) {
  return (UINTN)strtoul(String, NULL, 16);
}

/* ===== EDK2 BaseMemoryLib functions ===== */
static inline VOID *CopyMem(VOID *Dest, const VOID *Src, UINTN Length) {
  return memcpy(Dest, Src, Length);
}

static inline INTN CompareMem(const VOID *Buf1, const VOID *Buf2, UINTN Length) {
  return (INTN)memcmp(Buf1, Buf2, Length);
}

static inline VOID *ZeroMem(VOID *Buffer, UINTN Length) {
  return memset(Buffer, 0, Length);
}

/* ===== AsciiSPrint — simplified stub ===== */
static inline UINTN AsciiSPrint(CHAR8 *Buffer, UINTN BufferSize, const CHAR8 *Format, ...) {
  (void)Buffer; (void)BufferSize; (void)Format;
  return 0;
}

/* ===== Forward declarations for functions in KillSwitch.c ===== */
BOOLEAN ParseDateString(IN CONST CHAR8 *DateString, OUT UINT16 *Year, OUT UINT8 *Month, OUT UINT8 *Day);
INTN CompareDates(IN UINT16 Year1, IN UINT8 Month1, IN UINT8 Day1, IN UINT16 Year2, IN UINT8 Month2, IN UINT8 Day2);
EFI_STATUS ParseUuidString(IN CONST CHAR8 *UuidString, OUT UINT8 *UuidBytes);
KILL_SWITCH_RESULT ValidateKillSwitches(VOID);
BOOLEAN ValidateUuid(VOID);
BOOLEAN ValidateTpmEk(VOID);
BOOLEAN ValidateExpiry(VOID);
EFI_STATUS GetSmbiosUuid(OUT CHAR8 *UuidString, IN UINTN BufferSize);
EFI_STATUS GetTpmEkHash(OUT UINT8 *EkHash, IN UINTN HashSize);

#endif /* __EDK2_STUBS_H__ */
