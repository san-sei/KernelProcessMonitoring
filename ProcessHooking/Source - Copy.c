#include <ntddk.h>
#include "ntalpctyp.h"
#include <ntstrsafe.h>
#include <windef.h>
#include "TransferMethod.h"
#include "myArrayList.h"
#include <stdlib.h>

#ifndef _X86_
	#define _X86_
#endif
#pragma warning (disable: 4706)
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
int Unload(PDRIVER_OBJECT pDriverObject);
//NTSTATUS HookNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG *NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
#pragma alloc_text(INIT,DriverEntry)
#pragma alloc_text(PAGE, Unload)
//#pragma alloc_text(PAGE, HookNtProtectVirtualMemory)
// The structure of the SSDT.

typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, *PSSDT;

extern PSSDT KeServiceDescriptorTable; // Pointer to the SSDT.

//#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1)); // Used the get the service number.

//NtQueryInformationThread
typedef NTSTATUS(*pNtQueryInformationThread)(
	_In_      HANDLE          ThreadHandle,
	_In_      THREADINFOCLASS ThreadInformationClass,
	_Inout_   PVOID           ThreadInformation,
	_In_      ULONG           ThreadInformationLength,
	_Out_opt_ PULONG          ReturnLength
	);
pNtQueryInformationThread fnNtQueryInformationThread;
//end of QueryInformationThread

#define HookedFnCount 43
ULONG SSDTAddress[HookedFnCount];
ULONG OrigFnAddress[HookedFnCount];
//0
typedef NTSTATUS(*pNtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS(*pNtLoadDriver)(PUNICODE_STRING);
typedef NTSTATUS(*pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(*pNtDeleteValueKey)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS(*pNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(*pNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(*pNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(*pNtClose)(HANDLE);
//8
typedef NTSTATUS(*pNtCreateProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOL, HANDLE, HANDLE, HANDLE);
//9
typedef NTSTATUS(*pNtCreateProcessEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOL, HANDLE, HANDLE, HANDLE, BOOLEAN);
//10
typedef NTSTATUS(*pNtCreateThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PVOID, BOOLEAN);
//11
typedef NTSTATUS(*pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID);
//12
typedef NTSTATUS(*pNtAllocateVirtualMemory)(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
//13
typedef NTSTATUS(*pNtAlpcCreatePort)(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES);
//14
typedef NTSTATUS(*pNtAlpcConnectPort)(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, ULONG, PSID, PPORT_MESSAGE, PULONG, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER);
//15
typedef NTSTATUS(*pNtAlpcSendWaitReceivePort)(
	HANDLE, ULONG, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, PPORT_MESSAGE, PULONG, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER);
//16
typedef NTSTATUS(*pNtAssignProcessToJobObject)(HANDLE, HANDLE);
//17
typedef NTSTATUS(*pNtConnectPort)(PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PPORT_VIEW, PREMOTE_PORT_VIEW,
	PULONG, PVOID, PULONG);
//18
typedef NTSTATUS(*pNtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
//19
typedef NTSTATUS(*pNtCreateSection)(_Out_     PHANDLE SectionHandle, _In_      ACCESS_MASK DesiredAccess, _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_  PLARGE_INTEGER MaximumSize, _In_      ULONG SectionPageProtection, _In_      ULONG AllocationAttributes, _In_opt_  HANDLE FileHandle);
//20
typedef NTSTATUS(*pNtDeviceIoControlFile)(_In_   HANDLE FileHandle, _In_   HANDLE Event, _In_   PIO_APC_ROUTINE ApcRoutine, _In_   PVOID ApcContext, _Out_  PIO_STATUS_BLOCK IoStatusBlock, _In_   ULONG IoControlCode, _In_   PVOID InputBuffer, _In_   ULONG InputBufferLength, _Out_  PVOID OutputBuffer, _In_   ULONG OutputBufferLength);
//21
typedef NTSTATUS(*pNtDuplicateObject)(_In_       HANDLE SourceProcessHandle, _In_       HANDLE SourceHandle, _In_opt_   HANDLE TargetProcessHandle, _Out_opt_  PHANDLE TargetHandle, _In_       ACCESS_MASK DesiredAccess, _In_       ULONG HandleAttributes, _In_ ULONG Options);
//22
typedef NTSTATUS(*pNtFsControlFile)(_In_       HANDLE FileHandle, _In_opt_   HANDLE Event, _In_opt_   PIO_APC_ROUTINE ApcRoutine, _In_opt_   PVOID ApcContext, _Out_      PIO_STATUS_BLOCK IoStatusBlock, _In_       ULONG FsControlCode, _In_opt_   PVOID InputBuffer, _In_       ULONG InputBufferLength, _Out_opt_  PVOID OutputBuffer, _In_       ULONG OutputBufferLength);
//23
typedef NTSTATUS(*pNtMakeTemporaryObject)(_In_  HANDLE Handle);
//24
typedef NTSTATUS(*pNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
//25
typedef NTSTATUS(*pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG *NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
//26
typedef NTSTATUS(*pNtOpenThread)(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);
//27
typedef NTSTATUS(*pNtQueueApcThread)(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
//28
typedef NTSTATUS(*pNtReplaceKey)(_In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE Key, _In_ POBJECT_ATTRIBUTES ReplacedObjectAttributes);
//29
typedef NTSTATUS(*pNtRequestPort)(_In_ HANDLE PortHandle, _In_ PPORT_MESSAGE RequestMessage);
//30
typedef NTSTATUS(*pNtRequestWaitReplyPort)(_In_ HANDLE PortHandle, _Out_ PPORT_MESSAGE LpcReply, _In_ PPORT_MESSAGE LpcRequest);
//31
typedef NTSTATUS(*pNtRestoreKey)(_In_ HANDLE KeyHandle, _In_ HANDLE FileHandle, _In_ ULONG RestoreFlags);
//32
typedef NTSTATUS(*pNtSecureConnectPort)(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView OPTIONAL, PSID Sid OPTIONAL, PREMOTE_PORT_VIEW ServerView OPTIONAL, PULONG MaxMessageLength OPTIONAL, PVOID ConnectionInformation OPTIONAL, PULONG ConnectionInformationLength OPTIONAL);
//33
typedef NTSTATUS(*pNtSetContextThread)(HANDLE ThreadHandle, PCONTEXT Context);
//34
typedef NTSTATUS(*pNtSetSecurityObject)(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);
//35
typedef NTSTATUS(*pNtSetSystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, SIZE_T SystemInformationLength);
//36
typedef NTSTATUS(*pNtShutdownSystem)(SHUTDOWN_ACTION Action);
//37
typedef NTSTATUS(*pNtSuspendProcess)(HANDLE ProcessHandle);
//38
typedef NTSTATUS(*pNtSuspendThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
//39
typedef NTSTATUS(*pNtSystemDebugControl)(SYSDBG_COMMAND ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
//40
typedef NTSTATUS(*pNtTerminateThread)(HANDLE ThreadHandle, NTSTATUS ExitStatus);
//41
typedef NTSTATUS(*pNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
//42
typedef NTSTATUS(*pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID  BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
//...
pNtTerminateProcess fnNtTerminateProcess;
pNtLoadDriver fnNtLoadDriver;
pNtOpenProcess fnNtOpenProcess;
pNtDeleteValueKey fnNtDeleteValueKey;
pNtOpenFile fnNtOpenFile;
pNtCreateFile fnNtCreateFile;
pNtOpenKey fnNtOpenKey;
pNtClose fnNtClose;
pNtCreateProcess fnNtCreateProcess;
pNtCreateProcessEx fnNtCreateProcessEx;
pNtCreateThread fnNtCreateThread;
pNtCreateThreadEx fnNtCreateThreadEx;
pNtAllocateVirtualMemory fnNtAllocateVirtualMemory;
pNtAlpcCreatePort fnNtAlpcCreatePort;
pNtAlpcConnectPort fnNtAlpcConnectPort;
pNtAlpcSendWaitReceivePort fnNtAlpcSendWaitReceivePort;
pNtAssignProcessToJobObject fnNtAssignProcessToJobObject;
pNtConnectPort fnNtConnectPort;
pNtCreateKey fnNtCreateKey;
pNtCreateSection fnNtCreateSection;
pNtDeviceIoControlFile fnNtDeviceIoControlFile;
pNtDuplicateObject fnNtDuplicateObject;
pNtFsControlFile fnNtFsControlFile;
pNtMakeTemporaryObject fnNtMakeTemporaryObject;
pNtOpenSection fnNtOpenSection;
pNtProtectVirtualMemory fnNtProtectVirtualMemory;
pNtOpenThread fnNtOpenThread;
pNtQueueApcThread fnNtQueueApcThread;
pNtReplaceKey fnNtReplaceKey;
pNtRequestPort fnNtRequestPort;
pNtRequestWaitReplyPort fnNtRequestWaitReplyPort;
pNtRestoreKey fnNtRestoreKey;
pNtSecureConnectPort fnNtSecureConnectPort;
pNtSetContextThread fnNtSetContextThread;
pNtSetSecurityObject fnNtSetSecurityObject;
pNtSetSystemInformation fnNtSetSystemInformation;
pNtShutdownSystem fnNtShutdownSystem;
pNtSuspendProcess fnNtSuspendProcess;
pNtSuspendThread fnNtSuspendThread;
pNtSystemDebugControl fnNtSystemDebugControl;
pNtTerminateThread fnNtTerminateThread;
pNtUnloadDriver fnNtUnloadDriver;
pNtWriteVirtualMemory fnNtWriteVirtualMemory;

//[NtWriteVirtualMemory]
NTSTATUS HookNtWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID  BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToWrite,
	_Out_ PSIZE_T NumberOfBytesWritten
	)
{
	
	NTSTATUS _retStatus = fnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtWriteVirtualMemory(handle[in]='%d',pvoid[in]='%p',pvoid[in]='%p')\r\n",_ThreadExBuffer,
			ProcessHandle, BaseAddress, Buffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtWriteVirtualMemory");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtWriteVirtualMemory)");
		}
	}
	return _retStatus;
}
//[NtUnloadDriver]
NTSTATUS HookNtUnloadDriver(
	_In_ PUNICODE_STRING DriverServiceName
	)
{
	NTSTATUS _retStatus = fnNtUnloadDriver(DriverServiceName);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtUnloadDriver()\r\n", _ThreadExBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtUnloadDriver");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtUnloadDriver)");
		}
	}
	return _retStatus;
}
//[NtTerminateThread]
NTSTATUS HookNtTerminateThread(
	_In_ HANDLE ThreadHandle,
	_In_ NTSTATUS ExitStatus
	)
{
	NTSTATUS _retStatus = fnNtTerminateThread(ThreadHandle, ExitStatus);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtTerminateThread(handle[in]='%d')\r\n",_ThreadExBuffer,
			ThreadHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtTerminateThread");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtTerminateThread)");
		}
	}
	return _retStatus;
}
//[NtSystemDebugControl]
NTSTATUS HookNtSystemDebugControl(
	SYSDBG_COMMAND ControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength,
	PULONG ReturnLength
	)
{
	NTSTATUS _retStatus = fnNtSystemDebugControl(ControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtSystemDebugControl(pvoid[in]='%p',pvoid[out]='%p')\r\n",_ThreadExBuffer,
			InputBuffer, OutputBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtSystemDebugControl");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtSystemDebugControl)");
		}
	}
	return _retStatus;
}
//[NtSuspendThread]
NTSTATUS HookNtSuspendThread(
	_In_ HANDLE ThreadHandle,
	_In_ PULONG PreviousSuspendCount
	)
{
	NTSTATUS _retStatus = fnNtSuspendThread(ThreadHandle, PreviousSuspendCount);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtSuspendThread(handle[in]='%d')\r\n",_ThreadExBuffer,
			ThreadHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtSuspendThread");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtSuspendThread)");
		}
	}
	return _retStatus;
}

//[NtSuspendProcess]
NTSTATUS HookNtSuspendProcess(
	_In_ HANDLE ProcessHandle
	)
{
	NTSTATUS _retStatus = fnNtSuspendProcess(ProcessHandle);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtSuspendProcess(handle[in]='%d')\r\n",_ThreadExBuffer,
			ProcessHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtSuspendProcess");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtSuspendProcess)");
		}
	}
	return _retStatus;
}
//[NtShutdownSystem]
NTSTATUS HookNtShutdownSystem(
	_In_ SHUTDOWN_ACTION Action
	)
{
	NTSTATUS _retStatus = fnNtShutdownSystem(Action);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtShutdownSystem()\r\n", _ThreadExBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtShutdownSystem");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtShutdownSystem)");
		}
	}
	return _retStatus;
}
//[NtSetSystemInformation]
NTSTATUS HookNtSetSystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_In_ PVOID SystemInformation,
	_In_ SIZE_T SystemInformationLength
	)
{
	NTSTATUS _retStatus = fnNtSetSystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtSetSystemInformation()\r\n", _ThreadExBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtSetSystemInformation");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtSetSystemInformation)");
		}
	}
	return _retStatus;
}
//[NtSetSecurityObject]
NTSTATUS HookNtSetSecurityObject(
	_In_ HANDLE Handle,
	_In_ SECURITY_INFORMATION SecurityInformation,
	_In_ PSECURITY_DESCRIPTOR SecurityDescriptor
	)
{
	NTSTATUS _retStatus = fnNtSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtSetSecurityObject(handle[in]='%d')\r\n",_ThreadExBuffer,
			Handle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtSetSecurityObject");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtSetSecurityObject)");
		}
	}
	return _retStatus;
}
//[NtSetContextThread]
NTSTATUS HookNtSetContextThread(
	_In_ HANDLE ThreadHandle,
	_In_ PCONTEXT Context
	)
{
	NTSTATUS _retStatus = fnNtSetContextThread(ThreadHandle, Context);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtSetContextThread(handle[in]='%d')\r\n",_ThreadExBuffer,
			ThreadHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtSetContextThread");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtSetContextThread)");
		}
	}
	return _retStatus;
}
//[NtSecureConnectPort]
NTSTATUS HookNtSecureConnectPort(
	PHANDLE PortHandle,
	PUNICODE_STRING PortName,
	PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	PPORT_VIEW ClientView OPTIONAL,
	PSID Sid OPTIONAL,
	PREMOTE_PORT_VIEW ServerView OPTIONAL,
	PULONG MaxMessageLength OPTIONAL,
	PVOID ConnectionInformation OPTIONAL,
	PULONG ConnectionInformationLength OPTIONAL
	)
{
	NTSTATUS _retStatus = fnNtSecureConnectPort(PortHandle, PortName, SecurityQos, ClientView, Sid, ServerView,
		MaxMessageLength, ConnectionInformation, ConnectionInformationLength);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtSecureConnectPort(handle[out]='%d')\r\n",_ThreadExBuffer,
			(long)*PortHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtSecureConnectPort");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtSecureConnectPort)");
		}
	}
	return _retStatus;
}
//[NtRestoreKey]
NTSTATUS HookNtRestoreKey(
	_In_ HANDLE KeyHandle,
	_In_ HANDLE FileHandle,
	_In_ ULONG RestoreFlags
	)
{
	NTSTATUS _retStatus = fnNtRestoreKey(KeyHandle, FileHandle, RestoreFlags);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtRestoreKey(handle[in]='%d',handle[in]='%d')\r\n",_ThreadExBuffer,
			KeyHandle, FileHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtRestoreKey");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtRestoreKey)");
		}
	}
	return _retStatus;
}
//[NtRequestWaitReplyPort]
NTSTATUS HookNtRequestWaitReplyPort(
	_In_ HANDLE PortHandle,
	_Out_ PPORT_MESSAGE LpcReply,
	_In_ PPORT_MESSAGE LpcRequest
	)
{
	NTSTATUS _retStatus = fnNtRequestWaitReplyPort(PortHandle, LpcReply, LpcRequest);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtRequestWaitReplyPort(handle[in]='%d')\r\n",_ThreadExBuffer,
			PortHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtRequestWaitReplyPort");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtRequestWaitReplyPort)");
		}
	}
	return _retStatus;
}
//[NtRequestPort]
NTSTATUS HookNtRequestPort(
	_In_ HANDLE PortHandle,
	_In_ PPORT_MESSAGE RequestMessage
	)
{
	NTSTATUS _retStatus = fnNtRequestPort(PortHandle, RequestMessage);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtRequestPort(handle[in]='%d')\r\n",_ThreadExBuffer,
			PortHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtRequestPort");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtRequestPort)");
		}
	}
	return _retStatus;
}
//[NtReplaceKey]
NTSTATUS HookNtReplaceKey(
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE Key,
	_In_ POBJECT_ATTRIBUTES ReplacedObjectAttributes
	)
{
	NTSTATUS _retStatus = fnNtReplaceKey(ObjectAttributes, Key, ReplacedObjectAttributes);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtReplaceKey(handle[in]='%d')\r\n",_ThreadExBuffer,
			Key);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtReplaceKey");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtReplaceKey)");
		}
	}
	return _retStatus;
}
//[NtQueueApcThread]
NTSTATUS HookNtQueueApcThread(
	_In_ HANDLE ThreadHandle,
	_In_ PKNORMAL_ROUTINE ApcRoutine,
	_In_opt_ PVOID NormalContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
	)
{
	NTSTATUS _retStatus = fnNtQueueApcThread(ThreadHandle, ApcRoutine, NormalContext, SystemArgument1, SystemArgument2);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtQueueApcThread(handle[in]='%d')\r\n",_ThreadExBuffer,
			ThreadHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtQueueApcThread");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtQueueApcThread)");
		}
	}
	return _retStatus;
}
//[NtOpenThread]
NTSTATUS HookNtOpenThread(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PCLIENT_ID ClientId
	)
{
	NTSTATUS _retStatus = fnNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtOpenThread(handle[out]='%d',pclient_id[in]='%p')\r\n",_ThreadExBuffer,
			(long)*ThreadHandle, ClientId);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtOpenThread");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtOpenThread)");
		}
	}
	return _retStatus;
}
//[NtProtectVirtualMemory]
NTSTATUS HookNtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID *BaseAddress,
	_In_ ULONG *NumberOfBytesToProtect,
	_In_ ULONG NewAccessProtection,
	_Out_ PULONG OldAccessProtection
	)
{
	NTSTATUS _retStatus = fnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtProtectVirtualMemory(handle[in]='%d',pvoid[in]='%p')\r\n",_ThreadExBuffer,
			ProcessHandle, BaseAddress);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtProtectVirtualMemory");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtProtectVirtualMemory)");
		}
	}
	return _retStatus;
}
//[NtOpenSection]
NTSTATUS HookNtOpenSection(
	_Out_  PHANDLE SectionHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes
	)
{
	NTSTATUS _retStatus = fnNtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtOpenSection(handle[out]='%d')\r\n",_ThreadExBuffer,
			(long)*SectionHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtOpenSection");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtOpenSection)");
		}
	}
	return _retStatus;
}
//[NtMakeTemporaryObject]
NTSTATUS HookNtMakeTemporaryObject(
	_In_  HANDLE Handle
	)
{
	NTSTATUS _retStatus = fnNtMakeTemporaryObject(Handle);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtMakeTemporaryObject(handle[in]='%d')\r\n",_ThreadExBuffer,
			Handle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtMakeTemporaryObject");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtMakeTemporaryObject)");
		}
	}
	return _retStatus;
}
//[NtFsControlFile]
NTSTATUS HookNtFsControlFile(
	_In_       HANDLE FileHandle,
	_In_opt_   HANDLE Event,
	_In_opt_   PIO_APC_ROUTINE ApcRoutine,
	_In_opt_   PVOID ApcContext,
	_Out_      PIO_STATUS_BLOCK IoStatusBlock,
	_In_       ULONG FsControlCode,
	_In_opt_   PVOID InputBuffer,
	_In_       ULONG InputBufferLength,
	_Out_opt_  PVOID OutputBuffer,
	_In_       ULONG OutputBufferLength
	)
{
	NTSTATUS _retStatus = fnNtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength,
		OutputBuffer, OutputBufferLength);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtFsControlFile(handle[in]='%d',handle[in]='%d',pvoid[in]='%p',pvoid[out]='%p')\r\n",_ThreadExBuffer,
			FileHandle, Event, InputBuffer, OutputBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtFsControlFile");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtFsControlFile)");
		}
	}
	return _retStatus;
}
//[NtDuplicateObject]
NTSTATUS HookNtDuplicateObject(
	_In_       HANDLE SourceProcessHandle,
	_In_       HANDLE SourceHandle,
	_In_opt_   HANDLE TargetProcessHandle,
	_Out_opt_  PHANDLE TargetHandle,
	_In_       ACCESS_MASK DesiredAccess,
	_In_       ULONG HandleAttributes,
	_In_       ULONG Options
	)
{
	NTSTATUS _retStatus = fnNtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess,
		HandleAttributes, Options);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
		{
			if (TargetHandle != NULL)
				ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtDuplicateObject(handle[in]='%d',handle[in]='%d',handle[in]='%d',handle[out]='%d')\r\n",_ThreadExBuffer,
				SourceProcessHandle, SourceHandle, TargetProcessHandle, (long)*TargetHandle);
			else
				ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtDuplicateObject(handle[in]='%d',handle[in]='%d',handle[in]='%d',handle[out]='%d')\r\n",_ThreadExBuffer,
				SourceProcessHandle, SourceHandle, TargetProcessHandle, 0x0);
		}
		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtDuplicateObject");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtDuplicateObject)");
		}
	}
	return _retStatus;
}
//[NtDeviceIOControlFile]
NTSTATUS HookNtDeviceIoControlFile(
	_In_   HANDLE FileHandle,
	_In_   HANDLE Event,
	_In_   PIO_APC_ROUTINE ApcRoutine,
	_In_   PVOID ApcContext,
	_Out_  PIO_STATUS_BLOCK IoStatusBlock,
	_In_   ULONG IoControlCode,
	_In_   PVOID InputBuffer,
	_In_   ULONG InputBufferLength,
	_Out_  PVOID OutputBuffer,
	_In_   ULONG OutputBufferLength
	)
{
	NTSTATUS _retStatus = fnNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
		InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	//
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtDeviceIoControlFile(handle[in]='%d',handle[in]='%d',pvoid[in]='%p',pvoid[out]='%p')\r\n",_ThreadExBuffer,
			FileHandle, Event, InputBuffer, OutputBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtDeviceIoControlFile");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtDeviceIoControlFile)");
		}
	}
	return _retStatus;
}
//[NtCreateSection]
NTSTATUS HookNtCreateSection(
	_Out_     PHANDLE SectionHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_  PLARGE_INTEGER MaximumSize,
	_In_      ULONG SectionPageProtection,
	_In_      ULONG AllocationAttributes,
	_In_opt_  HANDLE FileHandle
	)
{
	NTSTATUS _retStatus = fnNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection,
		AllocationAttributes, FileHandle);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtCreateSection(handle[out]='%d',handle[in]='%d')\r\n",_ThreadExBuffer,
			(long)*SectionHandle, FileHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtCreateSection");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtCreateSection)");
		}
	}
	return _retStatus;
}
//[NtCreateKey]
NTSTATUS HookNtCreateKey(
	_Out_       PHANDLE KeyHandle,
	_In_        ACCESS_MASK DesiredAccess,
	_In_        POBJECT_ATTRIBUTES ObjectAttributes,
	_Reserved_  ULONG TitleIndex,
	_In_opt_    PUNICODE_STRING Class,
	_In_        ULONG CreateOptions,
	_Out_opt_   PULONG Disposition
	)
{
	NTSTATUS _retStatus = fnNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtCreateKey(handle[out]='%d')\r\n",_ThreadExBuffer,
			(long)*KeyHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtCreateKey");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtCreateKey)");
		}
	}
	return _retStatus;
}
//[NtConnectPort]
NTSTATUS NTAPI HookNtConnectPort(
	__out PHANDLE PortHandle,
	__in PUNICODE_STRING PortName,
	__in PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	__inout_opt PPORT_VIEW ClientView,
	__inout_opt PREMOTE_PORT_VIEW ServerView,
	__out_opt PULONG MaxMessageLength,
	__inout_opt PVOID ConnectionInformation,
	__inout_opt PULONG ConnectionInformationLength
	)
{
	NTSTATUS _retStatus = fnNtConnectPort(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength,
		ConnectionInformation, ConnectionInformationLength);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtConnectPort(handle[out]='%d')\r\n",_ThreadExBuffer,
			(long)*PortHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtConnectPort");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtConnectPort)");
		}
	}
	return _retStatus;
}
//[NtAssignProcessToJobObject]
NTSTATUS HookNtAssignProcessToJobObject(__in HANDLE _job, __in HANDLE _process)
{
	NTSTATUS _retStatus = fnNtAssignProcessToJobObject(_job, _process);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtAssignProcessToJobObject(handle[in]='%d',handle[in]='%d')\r\n",_ThreadExBuffer,
			_job, _process);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtAssignProcessToJobObject");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer (NtAssignProcessToJobObject)");
		}
	}
	return _retStatus;
}
//[NtAlpcSendWaitReceivePort]
NTSTATUS HookNtAlpcSendWaitReceivePort(
	__in HANDLE                             PortHandle,
	__in ULONG                              Flags,
	__in_opt PPORT_MESSAGE                  SendMessage,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES    SendMessageAttributes,
	__inout_opt PPORT_MESSAGE               ReceiveMessage,
	__inout_opt PULONG                      BufferLength,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES    ReceiveMessageAttributes,
	__in_opt PLARGE_INTEGER                 TimeOut
	)
{
	NTSTATUS _retStatus = fnNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage,
		BufferLength, ReceiveMessageAttributes, TimeOut);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtAlpcSendWaitReceivePort(handle[in]='%d')\r\n",_ThreadExBuffer,
			PortHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtAlpcSendWaitReceivePort");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
//[NtAlpcConnectPort]
NTSTATUS NTAPI HookNtAlpcConnectPort(
	__out PHANDLE                           PortHandle,
	__in PUNICODE_STRING                    PortName,
	__in POBJECT_ATTRIBUTES                 ObjectAttributes,
	__in_opt PALPC_PORT_ATTRIBUTES          PortAttributes,
	__in ULONG                              Flags,
	__in_opt PSID                           Sid,
	__inout PPORT_MESSAGE                   ConnectionMessage,
	__inout_opt PULONG                      BufferLength,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES    OutMessageAttributes,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES    InMessageAttributes,
	__in_opt PLARGE_INTEGER                 Timeout
	)
{
	NTSTATUS _retStatus = fnNtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, Sid, ConnectionMessage,
		BufferLength, OutMessageAttributes, InMessageAttributes, Timeout);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtAlpcConnectPort(handle[out]='%d')\r\n",_ThreadExBuffer,
			(long)*PortHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtAlpcConnectPort");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
//[LPC]
NTSTATUS NTAPI HookNtAlpcCreatePort(
	__out PHANDLE                   PortHandle,
	__in POBJECT_ATTRIBUTES         ObjectAttributes,
	__in_opt PALPC_PORT_ATTRIBUTES  PortAttributes
	)
{
	NTSTATUS _retStatus = fnNtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtAlpcCreatePort(handle[out]='%d')\r\n",_ThreadExBuffer,
			(long)*PortHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtAlpcCreatePort");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
//[NtAllocateVirtualMemory]
NTSTATUS HookNtAllocateVirtualMemory(
	_In_     HANDLE ProcessHandle,
	_Inout_  PVOID *BaseAddress,
	_In_     ULONG_PTR ZeroBits,
	_Inout_  PSIZE_T RegionSize,
	_In_     ULONG AllocationType,
	_In_     ULONG Protect
	)
{
	NTSTATUS _retStatus = fnNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtAllocateVirtualMemory(handle[in]='%d',pvoid[out]='%p')\r\n",_ThreadExBuffer,
			(long)ProcessHandle, BaseAddress);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtAllocateVirtualMemory");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
//[NtCreateThread]
NTSTATUS NTAPI HookNtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PVOID UserStack,
	IN BOOLEAN CreateSuspended
	)
{
	NTSTATUS _retStatus = fnNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext,
		UserStack, CreateSuspended);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
			//extended for createThread
			//check for the nested injected thraed***
			long ThreadID = -1, ProcessID = -1;
			NTSTATUS status;
			PEPROCESS Process;
			status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);
			if (NT_SUCCESS(status))
			{
				ProcessID = (long)PsGetProcessId(Process);
				DbgPrint("Process ID is '%d'", ProcessID);
				//KeSetEvent(Process, IO_NO_INCREMENT, FALSE);
				ObDereferenceObject(Process);
			}
			else
			{
				DbgPrint("ObRefrencedObjectByHandle has been failed for ProcessObject in CreateThread");
			}
			PETHREAD Thread;
			status = ObReferenceObjectByHandle(*ThreadHandle, 0, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL);
			if (NT_SUCCESS(status))
			{
				ThreadID = (long)PsGetThreadId(Thread);
				DbgPrint("Thread ID is '%d'", ThreadID);
				//KeSetEvent(Process, IO_NO_INCREMENT, FALSE);
				ObDereferenceObject(Thread);
			}
			else
			{
				DbgPrint("ObRefrencedObjectByHandle has been failed for ThreadObject in CreateThread");
			}
			// if process id of thsi thread not equales to myhookedProcessID then it is injected thread
			if (ProcessID != -1 && ThreadID != -1 && (unsigned long)ProcessID != *_myHookedProcessID)
			{
				//So, this thread injected to another process
				DbgPrint("Injected Thread ***************************************************************");
				additem(ThreadID, ProcessID);
			}
			//end of extension
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtCreateThread(handle[out]='%d',handle[in]='%d',pclient_id[out]='%p',pvoid[in]='%p'",_ThreadExBuffer,
			(long)*ThreadHandle, ProcessHandle, ClientId,UserStack);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtCreateThread");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
//[NtCreateThreadEx]
NTSTATUS NTAPI HookNtCreateThreadEx(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__in PVOID StartRoutine,
	__in_opt PVOID Argument,
	__in ULONG CreateFlags,
	__in_opt ULONG ZeroBits,
	__in_opt ULONG StackSize,
	__in_opt ULONG MaximumStackSize,
	__in_opt PVOID AttributeList
	)
{
	NTSTATUS _retStatus = fnNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
		StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);

	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		//check for the injected thraed***
		long ThreadID = -1, ProcessID = -1;
		NTSTATUS status;
		PEPROCESS Process;
		status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);
		if (NT_SUCCESS(status))
		{
			ProcessID = (long)PsGetProcessId(Process);
			DbgPrint("Process ID is '%d'", ProcessID);
			//KeSetEvent(Process, IO_NO_INCREMENT, FALSE);
			ObDereferenceObject(Process);
		}
		else
		{
			DbgPrint("ObRefrencedObjectByHandle has been failed for ProcessObject in CreateThreadEx");
		}
		PETHREAD Thread;
		status = ObReferenceObjectByHandle(*ThreadHandle, 0, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL);
		if (NT_SUCCESS(status))
		{
			ThreadID = (long)PsGetThreadId(Thread);
			DbgPrint("Thread ID is '%d'", ThreadID);
			//KeSetEvent(Process, IO_NO_INCREMENT, FALSE);
			ObDereferenceObject(Thread);
		}
		else
		{
			DbgPrint("ObRefrencedObjectByHandle has been failed for ThreadObjectin CreateThreadEx");
		}
		// if process id of thsi thread not equales to myhookedProcessID then it is injected thread
		if (ProcessID != -1 && ThreadID != -1 && (unsigned long)ProcessID != *_myHookedProcessID)
		{
			//So, this thread injected to another process
			DbgPrint("Injected Thread ***************************************************************");
			additem(ThreadID, ProcessID);
		}
		//***
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtCreateThreadEx(handle[out]='%d',handle[in]='%d',pvoid[in]='%p')\r\n",_ThreadExBuffer,
			(long)*ThreadHandle, ProcessHandle, StartRoutine);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtCreateThreadEx");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer 'NtCreateThreadEx'");
		}
	}
	return _retStatus;
}
//[NtCreateProcessEx]
NTSTATUS NTAPI HookNtCreateProcessEx
(
OUT PHANDLE ProcessHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
IN HANDLE ParentProcessHandle,
IN BOOL Inherit,
IN HANDLE SectionHandle OPTIONAL,
IN HANDLE DebugPort OPTIONAL,
IN HANDLE ExceptionPort OPTIONAL,
IN BOOLEAN InJob
)
{
	DbgPrint("NtCreateProcessEx by '%d'", PsGetCurrentProcessId());
	NTSTATUS _retStatus = fnNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcessHandle,
		Inherit, SectionHandle, DebugPort, ExceptionPort, InJob);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtCreateProcessEx(handle[out]='%d',handle[in]='%d',handle[in]='%d',handle[in]='%d',handle[in]='%d')\r\n",_ThreadExBuffer,
			(long)*ProcessHandle, ParentProcessHandle, SectionHandle, DebugPort, ExceptionPort);

		if (NT_SUCCESS(ntstatus))
		{
			//what is the filename this process created??
			PUNICODE_STRING _myCreatedProcessName;
			_myCreatedProcessName = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, 4096); // Allocate memory for the process name.
			if (NT_SUCCESS(ZwQueryInformationProcess(*ProcessHandle, 27, _myCreatedProcessName, 4096, NULL)))
			{
				DbgPrint("NtCreateProcessEx retrive '%ws'", _myCreatedProcessName->Buffer);
			}
			//
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtCreateProcessEx");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
//NtCreateProcess
NTSTATUS NTAPI HookNtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcessHandle,
	IN BOOL Inherit,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL)
{
	DbgPrint("NtCreateProcessEx by '%d'", PsGetCurrentProcessId());
	NTSTATUS _retStatus = fnNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcessHandle,
		Inherit, SectionHandle, DebugPort, ExceptionPort);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtCreateProcess(handle[out]='%d',handle[in]='%d',handle[in]='%d',handle[in]='%d',handle[in]='%d')\r\n",
			_ThreadExBuffer, (long)*ProcessHandle, ParentProcessHandle, SectionHandle, DebugPort, ExceptionPort);

		if (NT_SUCCESS(ntstatus))
		{
			//what is the filename this process created??
			PUNICODE_STRING _myCreatedProcessName;
			_myCreatedProcessName = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, 4096); // Allocate memory for the process name.
			if (NT_SUCCESS(ZwQueryInformationProcess(*ProcessHandle, 27, _myCreatedProcessName, 4096, NULL)))
			{
				DbgPrint("NtCreateProcess retrive '%ws'", _myCreatedProcessName->Buffer);
			}
			//
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtCreateProcess");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
//NtClose Hook
NTSTATUS HookNtClose(
	_In_  HANDLE Handle
	)
{
	int _handle = (int)Handle;
	NTSTATUS _retStatus = fnNtClose(Handle);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		//PLARGE_INTEGER _GMTtime = ExAllocatePool(NonPagedPool, 512);
		//PLARGE_INTEGER _Localtime = ExAllocatePool(NonPagedPool, 512);
		//KeQuerySystemTime(_GMTtime);
		//ExSystemTimeToLocalTime(_GMTtime, _Localtime);
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtClose(handle[in]='%d')\r\n", _ThreadExBuffer, _handle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtClose");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtClose)");
		}
	}
	return _retStatus;
}
//NtOpenKey Hook
NTSTATUS HookNtOpenKey(
	_Out_  PHANDLE KeyHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes
	)
{
	NTSTATUS _retStatus = fnNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtOpenKey(handle[out]='%d')\r\n", _ThreadExBuffer, (long)*KeyHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtOPenKey");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer(NtOpenKey)");
		}
	}
	return _retStatus;
}

//NtCreateFile hook
NTSTATUS HookNtCreateFile(
	_Out_     PHANDLE FileHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_      POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_     PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_  PLARGE_INTEGER AllocationSize,
	_In_      ULONG FileAttributes,
	_In_      ULONG ShareAccess,
	_In_      ULONG CreateDisposition,
	_In_      ULONG CreateOptions,
	_In_opt_  PVOID EaBuffer,
	_In_      ULONG EaLength
	)
{
	NTSTATUS _retStatus = fnNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
		ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtCreateFile(handle[out]='%d',pvoid[in]='%p')\r\n",_ThreadExBuffer,
			(long)*FileHandle, EaBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtCreateFile");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}

//NtOpenFile hook
NTSTATUS HookNtOpenFile(
	_Out_  PHANDLE FileHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_  PIO_STATUS_BLOCK IoStatusBlock,
	_In_   ULONG ShareAccess,
	_In_   ULONG OpenOptions
	)
{
	NTSTATUS _retStatus = fnNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtOpenFile(handle[out]='%d')\r\n",_ThreadExBuffer,
			(long)*FileHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtOpenFile");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}

// NtTerminateProcess hook

NTSTATUS HookNtTerminateProcess(
	_In_opt_  HANDLE ProcessHandle,
	_In_      NTSTATUS ExitStatus
	)
{
	//int _Terminatingflag = 0;
	NTSTATUS _retStatus = fnNtTerminateProcess(ProcessHandle, ExitStatus);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}

		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtTerminateProcess(handle[in]='%d')\r\n",_ThreadExBuffer,
			ProcessHandle);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtTerminateProcess");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	else
	{
		//get PID from Handle
		long ProcessID = -1;
		NTSTATUS status;
		PEPROCESS Process;
		status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);
		if (NT_SUCCESS(status))
		{
			ProcessID = (long)PsGetProcessId(Process);
			DbgPrint("Process ID is '%d'", ProcessID);
			//KeSetEvent(Process, IO_NO_INCREMENT, FALSE);
			ObDereferenceObject(Process);
		}
		else
		{
			DbgPrint("ObRefrencedObjectByHandle has been failed for ProcessObject in TerminateProcess");
		}
		//GetPID
		if (ProcessID == (long)*_myHookedProcessID)
		{
			DbgPrint("NtTerminateProcess(Process ID '%d') by this process ID '%d'", ProcessID, (long)PsGetCurrentProcessId());
			//this wrong comparision to compare two handle with each other, and must compare ID of each handle.
			/*
			WCHAR _buffer[MAX_LINE] = { 0 };
			NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
			if (NT_SUCCESS(_retStatus))
				ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"NtTerminateProcess called on this process.\r\n");

			if (NT_SUCCESS(ntstatus))
			{
				if (_logging(_buffer) == STATUS_SUCCESS)
					DbgPrint("NtTerminateProcess");
				else
					DbgPrint("Error in writing.%ws", _buffer);
			}
			else
			{
				DbgPrint("Error in input buffer");
			}
			*/
		}
	}
	return _retStatus;
}

// NtLoadDriver hook

NTSTATUS HookNtLoadDriver(
	_In_  PUNICODE_STRING DriverServiceName
	)
{
	NTSTATUS _retStatus = fnNtLoadDriver(DriverServiceName);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}

		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtLoadDriver()",_ThreadExBuffer);

		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtLoadDriver");
			else
				DbgPrint("Error in writing");
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}

// NtOpenProcess hook - Deny access to any processes with the name cmd.exe

NTSTATUS HookNtOpenProcess(
	_Out_     PHANDLE ProcessHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_      POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_  PCLIENT_ID ClientId
	)
{
	NTSTATUS _retStatus = fnNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}
		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer),
			L"%sNtOpenProcess(handle[out]='%d',pclient_id[in]='%p')\r\n", _ThreadExBuffer, (long)*ProcessHandle, ClientId);

		if (NT_SUCCESS(ntstatus))
		{
			//what is the filename that this process goes to opened??
			PUNICODE_STRING _myCreatedProcessName;
			_myCreatedProcessName = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, 4096); // Allocate memory for the process name.
			if (NT_SUCCESS(ZwQueryInformationProcess(*ProcessHandle, 27, _myCreatedProcessName, 4096, NULL)))
			{
				DbgPrint("NtOpenProcess retrive '%ws'", _myCreatedProcessName->Buffer);
			}
			//
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtOpenProcess");
			else
			{
				DbgPrint("Error in writing.%ws", _buffer);
			}
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}
// NtDeleteValueKey hook - Protect any values with the name abcdef from being deleted.

NTSTATUS HookNtDeleteValueKey(
	_In_  HANDLE KeyHandle,
	_In_  PUNICODE_STRING ValueName
	)
{
	NTSTATUS _retStatus = fnNtDeleteValueKey(KeyHandle, ValueName);
	int myThreadEx = 0;
	if (_myStatus && ((*_myHookedProcessID == (unsigned long)PsGetCurrentProcessId()) || (finditem((int)PsGetCurrentThreadId()) != -1 && (myThreadEx = 1))))
	{
		CHAR _ThreadExBuffer[20] = { 0 };
		CHAR _TempBuffer[20] = { 0 }; CHAR _TempBuffer2[20] = { 0 };
		if (myThreadEx)
		{
			_itoa_s(finditem((int)PsGetCurrentThreadId()), _TempBuffer2, 20, 10); strcat_s(_ThreadExBuffer, 20, _TempBuffer2);
			_itoa_s((int)PsGetCurrentThreadId(), _TempBuffer, 20, 10);
			strcat_s(_ThreadExBuffer, 20, ":");
			strcat_s(_ThreadExBuffer, 20, _TempBuffer);
			strcat_s(_ThreadExBuffer, 20, ";");
		}

		WCHAR _buffer[MAX_LINE] = { 0 };
		NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
		if (NT_SUCCESS(_retStatus))
			ntstatus = RtlStringCbPrintfW(_buffer, sizeof(_buffer), L"%sNtDeleteValueKey(handle[in]='%d')\r\n", _ThreadExBuffer, KeyHandle);
		if (NT_SUCCESS(ntstatus))
		{
			if (_logging(_buffer) == STATUS_SUCCESS)
				DbgPrint("NtDeleteValueKey");
			else
				DbgPrint("Error in writing.%ws", _buffer);
		}
		else
		{
			DbgPrint("Error in input buffer");
		}
	}
	return _retStatus;
}

int Unload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	DbgPrint("Unload routine called...\n");
	// Disable write protection.
	__asm
	{
		mov eax, cr0
			and eax, not 0x10000
			mov cr0, eax
	}
	// Unhook the SSDT.

	for (int _ix = 0; _ix < HookedFnCount; _ix++)
	{
		if (_ix == 3)
			continue;
		*(PULONG)SSDTAddress[_ix] = (ULONG)OrigFnAddress[_ix];
	}

	// Restore write protection.
	__asm
	{
		mov eax, cr0
			or eax, 0x10000
			mov cr0, eax
	}

	DbgPrint("NtTerminateProcess unhooked.\n");
	DbgPrint("NtLoadDriver unhooked.\n");
	DbgPrint("NtOpenProcess unhooked.\n");
	DbgPrint("NtDeleteValueKey unhooked.\n");
	DbgPrint("NtOpenFile unhooked.\n");
	DbgPrint("NtCreateFile unhooked.\n");
	DbgPrint("NtOpenKey unhooked.\n");
	DbgPrint("NtClose unhooked.\n");
	DbgPrint("NtCreateProcess unhooked.\n");
	//...
	/*
	UNICODE_STRING usDosDeviceName;
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\ProcessHooking");
	IoDeleteSymbolicLink(&usDosDeviceName);

	IoDeleteDevice(pDriverObject->DeviceObject);
	*/
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pRegistryPath;
	//Unload rutine
	pDriverObject->DriverUnload = Unload;
	//...
	//initializing memory
	_myHookedProcessName = (PWCHAR)ExAllocatePool(NonPagedPool, 4096);
	RtlZeroMemory(_myHookedProcessName, 4096);
	_myHookedProcessID = (unsigned long *)ExAllocatePool(NonPagedPool, 4);
	RtlZeroMemory(_myHookedProcessID, 4);
	//
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;
	DbgPrint("DriverEntry Called \r\n");
	//RtlInitUnicodeString initialize UnicodeString Structure{shortlen,maxlen,*begin)
	RtlInitUnicodeString(&usDriverName, L"\\Device\\ProcessHooking");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\ProcessHooking");

	NtStatus = IoCreateDevice(pDriverObject, 0,
		&usDriverName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE, &pDeviceObject);

	//...
	pDeviceObject->Flags |= IO_TYPE;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

	if (NtStatus != STATUS_SUCCESS)
	{
		DbgPrint("Error Creating Device");
		return -1;

	}

	DbgPrint("Device Created");

	//Create a Symbolic Link to the device. Example -> \Device\Example
	NtStatus = IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);

	if (NtStatus != STATUS_SUCCESS)
	{
		DbgPrint("error creating symbolic link to %ws, named: %ws", usDosDeviceName.Buffer, usDriverName);
		return -1;
	}

	DbgPrint("Created symbolic link to %ws, named: %ws", usDosDeviceName.Buffer, usDriverName.Buffer);

	UINT uiIndex = 0;
	for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
		pDriverObject->MajorFunction[uiIndex] = PH_UnSupportedFunction;

	//pDriverObject->MajorFunction[IRP_MJ_CLOSE] = PH_Close;
	//pDriverObject->MajorFunction[IRP_MJ_CREATE] = PH_Create;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PH_IoControl;
	//pDriverObject->MajorFunction[IRP_MJ_READ] = USE_READ_FUNCTION;
	//pDriverObject->MajorFunction[IRP_MJ_WRITE] = USE_WRITE_FUNCTION;

	//InitializeObjectAttributes
	// Get the service number.
	ULONG ServiceNumber[HookedFnCount];
	ServiceNumber[0] = 370;//NtTerminateProcess
	ServiceNumber[1] = 155;//NtLoadDriver
	ServiceNumber[2] = 190;//NtOpenProcess
	//ServiceNumber[3] = 106;//NtDeleteValueKey
	ServiceNumber[4] = 179;//NtOpenFile
	ServiceNumber[5] = 66;//NtCreateFile
	ServiceNumber[6] = 182;//NtOpenKey
	ServiceNumber[7] = 50;//NtClose
	ServiceNumber[8] = 0x004f;//NtCreateProcess
	ServiceNumber[9] = 0x0050;//NtCreateProcessEx
	ServiceNumber[10] = 0x0057;//NtCreateThread
	ServiceNumber[11] = 0x0058;//NtCreateThreadEx
	ServiceNumber[12] = 0x0013;//NtAllocateVirtualMemory
	ServiceNumber[13] = 0x0017;//NtNtAlpcCreatePort
	ServiceNumber[14] = 0x0016;//NtAlpcConnectPort
	ServiceNumber[15] = 0x0027;//NtAlpcSendWaitReceivePort
	ServiceNumber[16] = 0x002b;//NtAssignProcessToJobObject
	ServiceNumber[17] = 0x003b;//NtConnectPort
	ServiceNumber[18] = 0x0046;//NtCreateKey
	ServiceNumber[19] = 0x0054;//NtCreateSection
	ServiceNumber[20] = 0x006b;//NtDeviceIoControlFile
	ServiceNumber[21] = 0x006f;//NtDuplicateObject
	ServiceNumber[22] = 0x0086;//NtFsControlFile
	ServiceNumber[23] = 0x00a4;//NtMakeTemporaryObject
	ServiceNumber[24] = 0x00c2;//NtOpenSection
	ServiceNumber[25] = 215;//NtProtectVirtualMemory
	ServiceNumber[26] = 198;//NtOpenThread
	ServiceNumber[27] = 0x010d;//NtQueueApcThread
	ServiceNumber[28] = 0x0124;//NtReplaceKey
	ServiceNumber[29] = 0x012a;//NtRequestPort
	ServiceNumber[30] = 0x012b;//NtRequestWaitReplyPort
	ServiceNumber[31] = 0x012e;//NtRestoreKey
	ServiceNumber[32] = 0x0138;//NtSecureConnectPort
	ServiceNumber[33] = 0x013c;//NtSetContextThread
	ServiceNumber[34] = 0x015b;//NtSetSecurityObject
	ServiceNumber[35] = 0x015e;//NtSetSystemInformation
	ServiceNumber[36] = 0x0168;//NtShutdownSystem
	ServiceNumber[37] = 0x016e;//NtSuspendProcess
	ServiceNumber[38] = 0x016f;//NtSuspendThread
	ServiceNumber[39] = 0x0170;//NtSystemDebugControl
	ServiceNumber[40] = 0x0173;//NtTerminateThread
	ServiceNumber[41] = 0x017b;//NtUnloadDriver
	ServiceNumber[42] = 0x018f;//NtWriteVirtualMemory

	for (int _ix = 0; _ix < HookedFnCount; _ix++)
	{
		if (_ix == 3) continue;
		SSDTAddress[_ix] = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber[_ix] * 4;
		OrigFnAddress[_ix] = *(PULONG)SSDTAddress[_ix];
	}
	//NtQueryInformationThreadAddress***
	fnNtQueryInformationThread = (pNtQueryInformationThread)*(PULONG)((ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x00ec * 4);
	//***
	fnNtTerminateProcess = (pNtTerminateProcess)OrigFnAddress[0];
	fnNtLoadDriver = (pNtLoadDriver)OrigFnAddress[1];
	fnNtOpenProcess = (pNtOpenProcess)OrigFnAddress[2];
	//fnNtDeleteValueKey = (pNtDeleteValueKey)OrigFnAddress[3];
	fnNtOpenFile = (pNtOpenFile)OrigFnAddress[4];
	fnNtCreateFile = (pNtCreateFile)OrigFnAddress[5];
	fnNtOpenKey = (pNtOpenKey)OrigFnAddress[6];
	fnNtClose = (pNtClose)OrigFnAddress[7];
	fnNtCreateProcess = (pNtCreateProcess)OrigFnAddress[8];
	fnNtCreateProcessEx = (pNtCreateProcessEx)OrigFnAddress[9];//be careful
	fnNtCreateThread = (pNtCreateThread)OrigFnAddress[10];//be careful
	fnNtCreateThreadEx = (pNtCreateThreadEx)OrigFnAddress[11];//be careful
	fnNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)OrigFnAddress[12];
	fnNtAlpcCreatePort = (pNtAlpcCreatePort)OrigFnAddress[13];
	fnNtAlpcConnectPort = (pNtAlpcConnectPort)OrigFnAddress[14];
	fnNtAlpcSendWaitReceivePort = (pNtAlpcSendWaitReceivePort)OrigFnAddress[15];
	fnNtAssignProcessToJobObject = (pNtAssignProcessToJobObject)OrigFnAddress[16];
	fnNtConnectPort = (pNtConnectPort)OrigFnAddress[17];
	fnNtCreateKey = (pNtCreateKey)OrigFnAddress[18];
	fnNtCreateSection = (pNtCreateSection)OrigFnAddress[19];
	fnNtDeviceIoControlFile = (pNtDeviceIoControlFile)OrigFnAddress[20];
	fnNtDuplicateObject = (pNtDuplicateObject)OrigFnAddress[21];
	fnNtFsControlFile = (pNtFsControlFile)OrigFnAddress[22];
	fnNtMakeTemporaryObject = (pNtMakeTemporaryObject)OrigFnAddress[23];
	fnNtOpenSection = (pNtOpenSection)OrigFnAddress[24];
	fnNtProtectVirtualMemory = (pNtProtectVirtualMemory)OrigFnAddress[25];
	fnNtOpenThread = (pNtOpenThread)OrigFnAddress[26];
	fnNtQueueApcThread = (pNtQueueApcThread)OrigFnAddress[27];
	fnNtReplaceKey = (pNtReplaceKey)OrigFnAddress[28];
	fnNtRequestPort = (pNtRequestPort)OrigFnAddress[29];
	fnNtRequestWaitReplyPort = (pNtRequestWaitReplyPort)OrigFnAddress[30];
	fnNtRestoreKey = (pNtRestoreKey)OrigFnAddress[31];
	fnNtSecureConnectPort = (pNtSecureConnectPort)OrigFnAddress[32];
	fnNtSetContextThread = (pNtSetContextThread)OrigFnAddress[33];
	fnNtSetSecurityObject = (pNtSetSecurityObject)OrigFnAddress[34];
	fnNtSetSystemInformation = (pNtSetSystemInformation)OrigFnAddress[35];
	fnNtShutdownSystem = (pNtShutdownSystem)OrigFnAddress[36];
	fnNtSuspendProcess = (pNtSuspendProcess)OrigFnAddress[37];
	fnNtSuspendThread = (pNtSuspendThread)OrigFnAddress[38];
	fnNtSystemDebugControl = (pNtSystemDebugControl)OrigFnAddress[39];
	fnNtTerminateThread = (pNtTerminateThread)OrigFnAddress[40];
	fnNtUnloadDriver = (pNtUnloadDriver)OrigFnAddress[41];
	fnNtWriteVirtualMemory = (pNtWriteVirtualMemory)OrigFnAddress[42];

	// Disable write protection.
	__asm
	{
	mov eax, cr0
	and eax, not 0x10000
	mov cr0, eax
	}

	*(PULONG)SSDTAddress[0] = (ULONG)HookNtTerminateProcess;
	*(PULONG)SSDTAddress[1] = (ULONG)HookNtLoadDriver;
	*(PULONG)SSDTAddress[2] = (ULONG)HookNtOpenProcess;
	//*(PULONG)SSDTAddress[3] = (ULONG)HookNtDeleteValueKey;
	*(PULONG)SSDTAddress[4] = (ULONG)HookNtOpenFile;
	*(PULONG)SSDTAddress[5] = (ULONG)HookNtCreateFile;
	*(PULONG)SSDTAddress[6] = (ULONG)HookNtOpenKey;
	*(PULONG)SSDTAddress[7] = (ULONG)HookNtClose;
	*(PULONG)SSDTAddress[8] = (ULONG)HookNtCreateProcess;
	*(PULONG)SSDTAddress[9] = (ULONG)HookNtCreateProcessEx;
	*(PULONG)SSDTAddress[10] = (ULONG)HookNtCreateThread;
	*(PULONG)SSDTAddress[11] = (ULONG)HookNtCreateThreadEx;
	*(PULONG)SSDTAddress[12] = (ULONG)HookNtAllocateVirtualMemory;
	*(PULONG)SSDTAddress[13] = (ULONG)HookNtAlpcCreatePort;
	*(PULONG)SSDTAddress[14] = (ULONG)HookNtAlpcConnectPort;
	*(PULONG)SSDTAddress[15] = (ULONG)HookNtAlpcSendWaitReceivePort;
	*(PULONG)SSDTAddress[16] = (ULONG)HookNtAssignProcessToJobObject;
	*(PULONG)SSDTAddress[17] = (ULONG)HookNtConnectPort;
	*(PULONG)SSDTAddress[18] = (ULONG)HookNtCreateKey;
	*(PULONG)SSDTAddress[19] = (ULONG)HookNtCreateSection;
	*(PULONG)SSDTAddress[20] = (ULONG)HookNtDeviceIoControlFile;
	*(PULONG)SSDTAddress[21] = (ULONG)HookNtDuplicateObject;
	*(PULONG)SSDTAddress[22] = (ULONG)HookNtFsControlFile;
	*(PULONG)SSDTAddress[23] = (ULONG)HookNtMakeTemporaryObject;
	*(PULONG)SSDTAddress[24] = (ULONG)HookNtOpenSection;
	*(PULONG)SSDTAddress[25] = (ULONG)HookNtProtectVirtualMemory;
	*(PULONG)SSDTAddress[26] = (ULONG)HookNtOpenThread;
	*(PULONG)SSDTAddress[27] = (ULONG)HookNtQueueApcThread;
	*(PULONG)SSDTAddress[28] = (ULONG)HookNtReplaceKey;
	*(PULONG)SSDTAddress[29] = (ULONG)HookNtRequestPort;
	*(PULONG)SSDTAddress[30] = (ULONG)HookNtRequestWaitReplyPort;
	*(PULONG)SSDTAddress[31] = (ULONG)HookNtRestoreKey;
	*(PULONG)SSDTAddress[32] = (ULONG)HookNtSecureConnectPort;
	*(PULONG)SSDTAddress[33] = (ULONG)HookNtSetContextThread;
	*(PULONG)SSDTAddress[34] = (ULONG)HookNtSetSecurityObject;
	*(PULONG)SSDTAddress[35] = (ULONG)HookNtSetSystemInformation;
	*(PULONG)SSDTAddress[36] = (ULONG)HookNtShutdownSystem;
	*(PULONG)SSDTAddress[37] = (ULONG)HookNtSuspendProcess;
	*(PULONG)SSDTAddress[38] = (ULONG)HookNtSuspendThread;
	*(PULONG)SSDTAddress[39] = (ULONG)HookNtSystemDebugControl;
	*(PULONG)SSDTAddress[40] = (ULONG)HookNtTerminateThread;
	*(PULONG)SSDTAddress[41] = (ULONG)HookNtUnloadDriver;
	*(PULONG)SSDTAddress[42] = (ULONG)HookNtWriteVirtualMemory;

	// Restore write protection.
	__asm
	{
	mov eax, cr0
	or eax, 0x10000
	mov cr0, eax
	}


	/*
	DbgPrint("NtTerminateProcess address: %#x\n", OrigNtTerminateProcess);
	DbgPrint("NtLoadDriver address: %#x\n", OrigNtLoadDriver);
	DbgPrint("NtOpenProcess address: %#x\n", OrigNtOpenProcess);
	DbgPrint("NtDeleteValueKey address: %#x\n", OrigNtDeleteValueKey);
	DbgPrint("NtOpenFile address: %#x\n", OrigNtOpenFile);
	DbgPrint("NtCreateFile address: %#x\n", OrigNtCreateFile);
	DbgPrint("NtOpenKey address: %#x\n", OrigNtOpenKey);
	DbgPrint("NtClose address: %#x\n", OrigNtClose);
	DbgPrint("NtCreateProcess address: %#x\n", OrigNtCreateProcess);
	DbgPrint("NtCreateProcessEx address: %#x\n", OrigNtCreateProcessEx);
	DbgPrint("NtCreateThread address: %#x\n", OrigNtCreateThreadEx);
	DbgPrint("NtCreateThreadEx address: %#x\n", OrigNtCreateThread);

	DbgPrint("NtTerminateProcess hooked.\n");
	DbgPrint("NtLoadDriver hooked.\n");
	DbgPrint("NtOpenProcess hooked.\n");
	DbgPrint("NtDeleteValueKey hooked.\n");
	DbgPrint("NtOpenFile hooked.\n");
	DbgPrint("NtCreateFile hooked.\n");
	DbgPrint("NtOpenKey hooked.\n");
	DbgPrint("NtClose hooked.\n");
	DbgPrint("NtCreateProcess hooked.\n");
	DbgPrint("NtCreateProcessEx hooked.\n");
	*/
	DbgPrint("NtNtProtectVirtualMemory NEW9 address: %#x\n", OrigFnAddress[25]);
	DbgPrint("SSDT hook driver loaded.\n");
	return NtStatus;
}