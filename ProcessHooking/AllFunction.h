#include <ntddk.h>
#include "TransferMethod.h"
#include "ntalpctyp.h"
#include <ntstrsafe.h>
#include <windef.h>

NTSTATUS NtOpenThread(
	_Out_  PHANDLE ThreadHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes,
	_In_   PCLIENT_ID ClientId
	);
//
NTSYSAPI NTSTATUS NTAPI
NtProtectVirtualMemory(
IN HANDLE               ProcessHandle,
IN OUT PVOID            *BaseAddress,
IN OUT PULONG           NumberOfBytesToProtect,
IN ULONG                NewAccessProtection,
OUT PULONG              OldAccessProtection
);
//
NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(
IN HANDLE               ThreadHandle,
IN PIO_APC_ROUTINE      ApcRoutine,
IN PVOID                ApcRoutineContext OPTIONAL,
IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
IN ULONG                ApcReserved OPTIONAL);
//
NTSYSAPI NTSTATUS NTAPI NtReplaceKey(
IN POBJECT_ATTRIBUTES   NewHiveFileName,
IN HANDLE               KeyHandle,
IN POBJECT_ATTRIBUTES   BackupHiveFileName);
//
typedef struct _LPC_MESSAGE {
	USHORT                  DataLength;
	USHORT                  Length;
	USHORT                  MessageType;
	USHORT                  DataInfoOffset;
	CLIENT_ID               ClientId;
	ULONG                   MessageId;
	ULONG                   CallbackId;
} LPC_MESSAGE, *PLPC_MESSAGE;

NTSYSAPI NTSTATUS NTAPI NtRequestPort(
IN HANDLE               PortHandle,
IN PLPC_MESSAGE         Request);
//
NTSYSAPI NTSTATUS NTAPI NtRequestWaitReplyPort(
IN HANDLE               PortHandle,
IN PLPC_MESSAGE         Request,
OUT PLPC_MESSAGE        IncomingReply);
//
NTSYSAPI NTSTATUS NTAPI NtRestoreKey(
IN HANDLE               KeyHandle,
IN HANDLE               FileHandle,
IN ULONG                RestoreOption);
//
//Doxygen
NTSTATUS NTAPI NtSecureConnectPort(OUT PHANDLE  	PortHandle,
	IN PUNICODE_STRING  	PortName,
	IN PSECURITY_QUALITY_OF_SERVICE  	Qos,
	IN OUT PPORT_VIEW ClientView  	OPTIONAL,
	IN PSID ServerSid  	OPTIONAL,
	IN OUT PREMOTE_PORT_VIEW ServerView  	OPTIONAL,
	OUT PULONG MaxMessageLength  	OPTIONAL,
	IN OUT PVOID ConnectionInformation  	OPTIONAL,
	IN OUT PULONG ConnectionInformationLength  	OPTIONAL
	);
//
NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
IN HANDLE               ThreadHandle,
IN PCONTEXT             Context);
//
NTSTATUS ZwSetSecurityObject(
	_In_  HANDLE Handle,
	_In_  SECURITY_INFORMATION SecurityInformation,
	_In_  PSECURITY_DESCRIPTOR SecurityDescriptor
	);
//
//
/*NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(
IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
IN PVOID                SystemInformation,
IN ULONG                SystemInformationLength);*/
//
typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;
NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(
IN SHUTDOWN_ACTION      Action);
//
//Doxygen
NTSTATUS NTAPI NtSuspendProcess(IN HANDLE  	ProcessHandle);
//
NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
IN HANDLE               ThreadHandle,
OUT PULONG              PreviousSuspendCount OPTIONAL);
//
NTSYSAPI NTSTATUS NTAPI NtSystemDebugControl(
IN SYSDBG_COMMAND       Command,
IN PVOID                InputBuffer OPTIONAL,
IN ULONG                InputBufferLength,
OUT PVOID               OutputBuffer OPTIONAL,
IN ULONG                OutputBufferLength,
OUT PULONG              ReturnLength OPTIONAL);
//
