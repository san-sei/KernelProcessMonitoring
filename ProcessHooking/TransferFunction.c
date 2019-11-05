/**********************************************************************
*
*  Toby Opferman
*
*  Driver PH
*
*  This PH is for educational purposes only.  I license this source
*  out for use in learning how to write a device driver.
*
*     Driver Functionality
**********************************************************************/

//#define _X86_ 
#pragma warning(disable:4116)

//#include <ntddk.h>
#include <wdm.h>
#include "TransferMethod.h"
#include "IOCTLFn.h"
#include <stdlib.h>
#include <ntstrsafe.h>
/**********************************************************************
* Internal Functions
**********************************************************************/
BOOLEAN PH_IsStringTerminated(PCHAR pString, UINT uiLength, UINT *pdwStringLength);
NTSTATUS PH_HandleSampleIoctl_DirectInIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten);
NTSTATUS PH_HandleSampleIoctl_DirectOutIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten);
NTSTATUS PH_HandleSampleIoctl_BufferedIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten);
NTSTATUS PH_HandleSampleIoctl_NeitherIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten);
NTSTATUS _getLogFileHandle(PWCHAR _Path, PHANDLE handle);
NTSTATUS _logging(PWCHAR _buffer);

/*#pragma alloc_text(PAGE, PH_Create) 
#pragma alloc_text(PAGE, PH_Close) 
#pragma alloc_text(PAGE, PH_IoControl) 
#pragma alloc_text(PAGE, PH_ReadDirectIO)
#pragma alloc_text(PAGE, PH_ReadBufferedIO)
#pragma alloc_text(PAGE, PH_ReadNeither)
#pragma alloc_text(PAGE, PH_WriteDirectIO)
#pragma alloc_text(PAGE, PH_WriteBufferedIO)
#pragma alloc_text(PAGE, PH_WriteNeither)*/
#pragma alloc_text(PAGE, PH_UnSupportedFunction)
#pragma alloc_text(PAGE, PH_IsStringTerminated)
#pragma alloc_text(PAGE, PH_HandleSampleIoctl_DirectInIo)
#pragma alloc_text(PAGE, PH_HandleSampleIoctl_DirectOutIo)
#pragma alloc_text(PAGE, PH_HandleSampleIoctl_NeitherIo)
#pragma alloc_text(PAGE, PH_HandleSampleIoctl_DirectInIo)



/**********************************************************************
*
*  PH_Create
*
*    This is called when an instance of this driver is created (CreateFile)
*
**********************************************************************/
/*NTSTATUS PH_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject); UNREFERENCED_PARAMETER(Irp);
	NTSTATUS NtStatus = STATUS_SUCCESS;
	DbgPrint("PH_Create Called \r\n");

	return NtStatus;
}*/

/**********************************************************************
*
*  PH_Close
*
*    This is called when an instance of this driver is closed (CloseHandle)
*
**********************************************************************/
/*NTSTATUS PH_Close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject); UNREFERENCED_PARAMETER(Irp);
	NTSTATUS NtStatus = STATUS_SUCCESS;
	DbgPrint("PH_Close Called \r\n");

	return NtStatus;
}*/



/**********************************************************************
*
*  PH_IoControl
*
*    This is called when an IOCTL is issued on the device handle (DeviceIoControl)
*
**********************************************************************/
NTSTATUS PH_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject); UNREFERENCED_PARAMETER(Irp);
	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	UINT dwDataWritten = 0;

	DbgPrint("PH_IoControl Called \r\n");

	/*
	* Each time the IRP is passed down the driver stack a new stack location is added
	* specifying certain parameters for the IRP to the driver.
	*/
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

	if (pIoStackIrp) /* Should Never Be NULL! */
	{
		switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_PH_SAMPLE_DIRECT_IN_IO:
			NtStatus = PH_HandleSampleIoctl_DirectInIo(Irp, pIoStackIrp, &dwDataWritten);
			break;

		case IOCTL_PH_SAMPLE_DIRECT_OUT_IO:
			NtStatus = PH_HandleSampleIoctl_DirectOutIo(Irp, pIoStackIrp, &dwDataWritten);
			break;

		case IOCTL_PH_SAMPLE_BUFFERED_IO:
			NtStatus = PH_HandleSampleIoctl_BufferedIo(Irp, pIoStackIrp, &dwDataWritten);
			break;

		case IOCTL_PH_SAMPLE_NEITHER_IO:
			NtStatus = PH_HandleSampleIoctl_NeitherIo(Irp, pIoStackIrp, &dwDataWritten);
			break;
		}
	}

	/*
	* This does not always need to be completed in this manner.  The I/O Manager is friendly
	* and in the simple case (as this driver is implemented) the IRP will be completed
	* by IoCompleteRequest() and the Status will be set to the return value.
	*
	* What will not be set however is the "Information" field, it cannot be set to how many bytes
	* were read or written obviously because the I/O Manager does not know, only your device
	* driver does.
	*
	* There are cases where you will need to complete the IRP and set the status however
	* our simple driver does not require that.
	*
	* In the Write operation the "bytes written" is really only used as an informant to
	* the application.  The Read operation is a bit different.  For PH, some types of buffering
	* it may not matter if you set the number of bytes read.  For PH "Neither" you write
	* directly into the user mode buffer so the user mode gets the data even if you don't
	* tell it the amount.  However if you remember how buffered I/O works?  It makes a copy
	* in memory.  If the I/O manager doesn't know the size then it can't copy it back to the
	* user mode buffer.
	*
	*
	* IO_NO_INCREMENT - What is this?  If an IRP request is taking a long time you may want to help
	* the scheduler to re-schedule the thread as soon as possible.  For PH perhaps it issued
	* a network request and went to sleep.  Then on another thread the network request completes
	* You may want to use one of the pre-defined constants or your own to increment the priority of
	* that thread to be rescheduled being since it hasn't been scheduled in a while.
	*
	*/

	Irp->IoStatus.Status = NtStatus;
	Irp->IoStatus.Information = dwDataWritten;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return NtStatus;

}






/**********************************************************************
*
*  PH_WriteDirectIO
*
*    This is called when a write is issued on the device handle (WriteFile/WriteFileEx)
*
*    This version uses Direct I/O
*
**********************************************************************/


/**********************************************************************
*
*  PH_WriteBufferedIO
*
*    This is called when a write is issued on the device handle (WriteFile/WriteFileEx)
*
*    This version uses Buffered I/O
*
**********************************************************************/


/**********************************************************************
*
*  PH_WriteNeither
*
*    This is called when a write is issued on the device handle (WriteFile/WriteFileEx)
*
*    This version uses Neither buffered or direct I/O.  User mode memory is
*    read directly.
*
**********************************************************************/



/**********************************************************************
*
*  PH_ReadDirectIO
*
*    This is called when a read is issued on the device handle (ReadFile/ReadFileEx)
*
*    This version uses Direct I/O
*
**********************************************************************/

/**********************************************************************
*
*  PH_ReadBufferedIO
*
*    This is called when a read is issued on the device handle (ReadFile/ReadFileEx)
*
*    This version uses Buffered I/O
*
**********************************************************************/

/**********************************************************************
*
*  PH_ReadNeither
*
*    This is called when a Read is issued on the device handle (ReadFile/ReadFileEx)
*
*    This version uses Neither buffered or direct I/O.  User mode memory is
*    written directly.
*
**********************************************************************/



/**********************************************************************
*
*  PH_UnSupportedFunction
*
*    This is called when a major function is issued that isn't supported.
*
**********************************************************************/
NTSTATUS PH_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject); UNREFERENCED_PARAMETER(Irp);
	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
	DbgPrint("PH_UnSupportedFunction Called \r\n");

	return NtStatus;
}


/**********************************************************************
*
*  PH_IsStringTerminated
*
*    Simple function to determine a string is NULL terminated.
*
**** We could validate also the characters in the string are printable! ***
*
**********************************************************************/
BOOLEAN PH_IsStringTerminated(PCHAR pString, UINT uiLength, UINT *pdwStringLength)
{
	BOOLEAN bStringIsTerminated = FALSE;
	UINT uiIndex = 0;

	DbgPrint("PH_IsStringTerminated(0x%0x, %d)\r\n", pString, uiLength);

	*pdwStringLength = 0;

	while (uiIndex < uiLength && bStringIsTerminated == FALSE)
	{
		if (pString[uiIndex] == '\0')
		{
			*pdwStringLength = uiIndex + 1; /* Include the total count we read, includes the NULL */
			bStringIsTerminated = TRUE;
			DbgPrint("  String Is Terminated!\r\n");
		}
		else
		{
			uiIndex++;
		}
	}

	return bStringIsTerminated;
}


/**********************************************************************
*
*  PH_HandleSampleIoctl_DirectInIo
*
*    Sample IOCTL TO Handle Direct In I/O
*
*
**********************************************************************/
NTSTATUS PH_HandleSampleIoctl_DirectInIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten)
{
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	PCHAR pInputBuffer;
	PCHAR pOutputBuffer;
	UINT dwDataRead = 0;// , dwDataWritten = 0;
	PCHAR pReturnData = "IOCTL - Direct In I/O From Kernel!";
	UINT dwDataSize = sizeof("IOCTL - Direct In I/O From Kernel!");
	DbgPrint("PH_HandleSampleIoctl_DirectInIo Called \r\n");

	/*
	* METHOD_IN_DIRECT
	*
	*    Input Buffer = Irp->AssociatedIrp.SystemBuffer
	*    Ouput Buffer = Irp->MdlAddress
	*
	*    Input Size   =  Parameters.DeviceIoControl.InputBufferLength
	*    Output Size  =  Parameters.DeviceIoControl.OutputBufferLength
	*
	* What's the difference between METHOD_IN_DIRECT && METHOD_OUT_DIRECT?
	*
	* This function is actually *WRONG*!!!!  We are using the output buffer
	* as an output buffer!  The difference is that METHOD_IN_DIRECT creates
	* an MDL for the outputbuffer with *READ* access so the user mode application
	* can send large amounts of data to the driver for reading.
	*
	* METHOD_OUT_DIRECT creates an MDL for the outputbuffer with *WRITE* access so the user mode
	* application can recieve large amounts of data from the driver!
	*
	* In both cases, the Input buffer is in the same place, the SystemBuffer.  There is a lot
	* of consfusion as people do think that the MdlAddress contains the input buffer and this
	* is not true in either case.
	*/

	pOutputBuffer = NULL;

	if (Irp->MdlAddress)
	{
		pOutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	}

	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (pInputBuffer && pOutputBuffer)
	{

		/*
		* We need to verify that the string is NULL terminated. Bad things can happen
		* if we access memory not valid while in the Kernel.
		*/
		if (PH_IsStringTerminated(pInputBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength, &dwDataRead))
		{
			DbgPrint("UserModeMessage = '%s'", pInputBuffer);

			DbgPrint("%i >= %i", pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength, dwDataSize);

			if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength >= dwDataSize)
			{
				/*
				* We use "RtlCopyMemory" in the kernel instead of memcpy.
				* RtlCopyMemory *IS* memcpy, however it's best to use the
				* wrapper in case this changes in the future.
				*/
				RtlCopyMemory(pOutputBuffer, pReturnData, dwDataSize);
				*pdwDataWritten = dwDataSize;
				NtStatus = STATUS_SUCCESS;
			}
			else
			{
				*pdwDataWritten = dwDataSize;
				NtStatus = STATUS_BUFFER_TOO_SMALL;
			}

		}
	}

	return NtStatus;
}


/**********************************************************************
*
*  PH_IsStringTerminated
*
*    Sample IOCTL TO Handle Direct Out I/O
*
*
**********************************************************************/
NTSTATUS PH_HandleSampleIoctl_DirectOutIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten)
{
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	PCHAR pInputBuffer;
	PCHAR pOutputBuffer;
	UINT dwDataRead = 0;// , dwDataWritten = 0;
	PCHAR pReturnData = "IOCTL - Direct Out I/O From Kernel!";
	UINT dwDataSize = sizeof("IOCTL - Direct Out I/O From Kernel!");
	DbgPrint("PH_HandleSampleIoctl_DirectOutIo Called \r\n");

	/*
	* METHOD_OUT_DIRECT
	*
	*    Input Buffer = Irp->AssociatedIrp.SystemBuffer
	*    Ouput Buffer = Irp->MdlAddress
	*
	*    Input Size   =  Parameters.DeviceIoControl.InputBufferLength
	*    Output Size  =  Parameters.DeviceIoControl.OutputBufferLength
	*
	* What's the difference between METHOD_IN_DIRECT && METHOD_OUT_DIRECT?
	*
	* The function which we implemented METHOD_IN_DIRECT is actually *WRONG*!!!!  We are using the output buffer
	* as an output buffer!  The difference is that METHOD_IN_DIRECT creates
	* an MDL for the outputbuffer with *READ* access so the user mode application
	* can send large amounts of data to the driver for reading.
	*
	* METHOD_OUT_DIRECT creates an MDL for the outputbuffer with *WRITE* access so the user mode
	* application can recieve large amounts of data from the driver!
	*
	* In both cases, the Input buffer is in the same place, the SystemBuffer.  There is a lot
	* of consfusion as people do think that the MdlAddress contains the input buffer and this
	* is not true in either case.
	*/


	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = NULL;

	if (Irp->MdlAddress)
	{
		pOutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	}

	if (pInputBuffer && pOutputBuffer)
	{

		/*
		* We need to verify that the string is NULL terminated. Bad things can happen
		* if we access memory not valid while in the Kernel.
		*/
		if (PH_IsStringTerminated(pInputBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength, &dwDataRead))
		{
			DbgPrint("UserModeMessage = '%s'", pInputBuffer);
			DbgPrint("%i >= %i", pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength, dwDataSize);
			if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength >= dwDataSize)
			{
				/*
				* We use "RtlCopyMemory" in the kernel instead of memcpy.
				* RtlCopyMemory *IS* memcpy, however it's best to use the
				* wrapper in case this changes in the future.
				*/
				RtlCopyMemory(pOutputBuffer, pReturnData, dwDataSize);
				*pdwDataWritten = dwDataSize;
				NtStatus = STATUS_SUCCESS;
			}
			else
			{
				*pdwDataWritten = dwDataSize;
				NtStatus = STATUS_BUFFER_TOO_SMALL;
			}
		}
	}

	return NtStatus;
}


/**********************************************************************
*
*  PH_IsStringTerminated
*
*    Sample IOCTL TO Handle Buffered I/O
*
*
**********************************************************************/
NTSTATUS PH_HandleSampleIoctl_BufferedIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten)
{
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	PCHAR pInputBuffer;
	PCHAR pOutputBuffer;
	UINT dwDataRead = 0;// , dwDataWritten = 0;
	
	CHAR pReturnData[512] = { 0 };
	
	DbgPrint("PH_HandleSampleIoctl_BufferedIo Called \r\n");

	/*
	* METHOD_BUFFERED
	*
	*    Input Buffer = Irp->AssociatedIrp.SystemBuffer
	*    Ouput Buffer = Irp->AssociatedIrp.SystemBuffer
	*
	*    Input Size   =  Parameters.DeviceIoControl.InputBufferLength
	*    Output Size  =  Parameters.DeviceIoControl.OutputBufferLength
	*
	*    Since they both use the same location so the "buffer" allocated by the I/O
	*    manager is the size of the larger value (Output vs. Input)
	*/


	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (pInputBuffer && pOutputBuffer)
	{

		/*
		* We need to verify that the string is NULL terminated. Bad things can happen
		* if we access memory not valid while in the Kernel.
		*/
		if (PH_IsStringTerminated(pInputBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength, &dwDataRead))
		{
			if (pInputBuffer[0] != '#')
			{
				_myStatus = 0;
				//spliting buffer
				char _myhprocess[512] = { 0 };
				char _myhthread[512] = { 0 };
				char _myProcessID[512] = { 0 };
				int _ix = 0, _ix2 = 0, _ix3 = 0;
				while (pInputBuffer[_ix] != ',')
				{
					_myhprocess[_ix] = pInputBuffer[_ix];
					_ix++;
				}
				_ix++;
				while (pInputBuffer[_ix] != ',')
				{
					_myhthread[_ix2++] = pInputBuffer[_ix++];
				}
				_ix++;
				while (pInputBuffer[_ix] != '\0')
				{
					_myProcessID[_ix3++] = pInputBuffer[_ix++];
				}
				DbgPrint("resived message is ProcessHandle[%s]ThreadHandle[%s]ProcessID[%s]", _myhprocess, _myhthread, _myProcessID);
				//
				//Set process ID in Public Variable HookedProcessID
				//
				RtlZeroMemory(_myHookedProcessID, 4);
				*_myHookedProcessID = atol(_myProcessID);
				_myHookedProcessHandle = (HANDLE)atoi(_myhprocess);
				//
				//Set Process path address with NtQueryInformation from Process Handle for exciting
				//
				HANDLE hp, ht;
				hp = (HANDLE)atoi(_myhprocess);
				ht = (HANDLE)atoi(_myhthread);
				PUNICODE_STRING _myHookedProcess;
				_myHookedProcess = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, 4096); // Allocate memory for the process name.
				if (NT_SUCCESS(ZwQueryInformationProcess(hp, 27, _myHookedProcess, 4096, NULL)))
				{
					DbgPrint("processname = '%ws', '%d'\n", _myHookedProcess->Buffer, _myHookedProcess->Length);
					RtlZeroMemory(_myHookedProcessName, 4096);
					RtlCopyMemory(_myHookedProcessName, _myHookedProcess->Buffer, _myHookedProcess->Length);
					DbgPrint("processname in allocated memory = '%ws'\n", _myHookedProcessName);// , rtlun _myHookedProcess->Length);
					//everything is Ok..

					if (_getLogFileHandle(_myHookedProcessName, &_myLogFileHandle) == STATUS_SUCCESS)
					{
						_myStatus = 1;
						DbgPrint("file is created and handle is [%d]", _myLogFileHandle);
					}
					else
					{
						DbgPrint("Cann't create file; Something goes to wrong.");
					}
					RtlCopyMemory(pReturnData, _myProcessID, strlen(_myProcessID));
				}
				ExFreePool(_myHookedProcess);
				//
				//return some data to user land for entertainment talking
				//
				DbgPrint("%i >= %i", pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength, strlen(pReturnData));
				if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength >= strlen(pReturnData))
				{
					/*
					* We use "RtlCopyMemory" in the kernel instead of memcpy.
					* RtlCopyMemory *IS* memcpy, however it's best to use the
					* wrapper in case this changes in the future.
					*/
					RtlCopyMemory(pOutputBuffer, pReturnData, strlen(pReturnData));

					*pdwDataWritten = strlen(pReturnData);

					NtStatus = STATUS_SUCCESS;
				}
				else
				{
					*pdwDataWritten = sizeof(pReturnData);
					NtStatus = STATUS_BUFFER_TOO_SMALL;
				}
				//
			}
			else
			{
				DbgPrint("resived message is [%s]", pInputBuffer);
				DbgPrint("ready to clear everything", pInputBuffer);
				if (_myStatus)
				{
					ZwClose(_myLogFileHandle);
					DbgPrint("file closed.");
				}
				else
				{
					DbgPrint("file not found for closing.");
				}
				//
				_myStatus = 0;//disable logging
				//
				char _sourceBuffer[10] = { 0 };
				strcpy_s(_sourceBuffer, 10, "#Done#");
				
				RtlCopyMemory(pReturnData, _sourceBuffer, strlen(_sourceBuffer));
				//
				//return some data to user land for entertainment talking
				//
				DbgPrint("%i >= %i", pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength, strlen(pReturnData));
				if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength >= strlen(pReturnData))
				{
					/*
					* We use "RtlCopyMemory" in the kernel instead of memcpy.
					* RtlCopyMemory *IS* memcpy, however it's best to use the
					* wrapper in case this changes in the future.
					*/
					RtlCopyMemory(pOutputBuffer, pReturnData, strlen(pReturnData));

					*pdwDataWritten = strlen(pReturnData);
					NtStatus = STATUS_SUCCESS;
				}
				else
				{
					*pdwDataWritten = sizeof(pReturnData);
					NtStatus = STATUS_BUFFER_TOO_SMALL;
				}
				//
			}
		}
	}
	return NtStatus;
}

NTSTATUS _getLogFileHandle(PWCHAR _Path, PHANDLE handle)
{
	DbgPrint("in _getLogFileHandle _path is[%ws]", _Path);
	WCHAR myFileName[_MAX_PATH];
	WCHAR mytxtPath[_MAX_PATH];
	_wsplitpath_s(_Path, NULL, 0, NULL, 0, myFileName, sizeof(myFileName), NULL, 0);
	RtlStringCbPrintfW(mytxtPath, sizeof(mytxtPath), L"\\DosDevices\\C:\\%ws.txt", myFileName);
	DbgPrint("mytxtpath is[%ws]", mytxtPath);
	
	UNICODE_STRING     uniName;
	OBJECT_ATTRIBUTES  objAttr;

	RtlInitUnicodeString(&uniName, mytxtPath);//L"\\DosDevices\\C:\\log.txt");  // or L"\\SystemRoot\\example.txt"
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK    ioStatusBlock;

	// Do not try to perform any file operations at higher IRQL levels.
	// Instead, you may use a work item or a system worker thread to perform file operations.

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	ntstatus = ZwCreateFile(handle,
		GENERIC_WRITE,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	return ntstatus;
}

NTSTATUS _logging(PWCHAR _buffer)
{
	//DbgPrint("_buffer in _logging routine is [%ws]", _buffer);
	IO_STATUS_BLOCK    ioStatusBlock;
	size_t  cb;
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	if (_myStatus)
	{

		ntstatus = RtlStringCbLengthW(_buffer, MAX_LINE*sizeof(WCHAR), &cb);
		if (NT_SUCCESS(ntstatus))
		{
			ntstatus = ZwWriteFile(_myLogFileHandle, NULL, NULL, NULL, &ioStatusBlock,
				_buffer, cb, NULL, NULL);
		}
	}
	return ntstatus;
}


/**********************************************************************
*
*  PH_IsStringTerminated
*
*    Sample IOCTL TO Handle Neither I/O
*
*
**********************************************************************/
NTSTATUS PH_HandleSampleIoctl_NeitherIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *pdwDataWritten)
{
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	PCHAR pInputBuffer;
	PCHAR pOutputBuffer;
	UINT dwDataRead = 0;// , dwDataWritten = 0;
	PCHAR pReturnData = "IOCTL - Neither I/O From Kernel!";
	UINT dwDataSize = sizeof("IOCTL - Neither I/O From Kernel!");

	DbgPrint("PH_HandleSampleIoctl_NeitherIo Called \r\n");

	/*
	* METHOD_NEITHER
	*
	*    Input Buffer = Parameters.DeviceIoControl.Type3InputBuffer
	*    Ouput Buffer = Irp->UserBuffer
	*
	*    Input Size   =  Parameters.DeviceIoControl.InputBufferLength
	*    Output Size  =  Parameters.DeviceIoControl.OutputBufferLength
	*
	*/


	pInputBuffer = pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
	pOutputBuffer = Irp->UserBuffer;

	if (pInputBuffer && pOutputBuffer)
	{

		/*
		* We need this in an exception handler or else we could trap.
		*/
		__try {

			ProbeForRead(pInputBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength, TYPE_ALIGNMENT(char));

			/*
			* We need to verify that the string is NULL terminated. Bad things can happen
			* if we access memory not valid while in the Kernel.
			*/
			if (PH_IsStringTerminated(pInputBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength, &dwDataRead))
			{
				DbgPrint("UserModeMessage = '%s'", pInputBuffer);

				ProbeForWrite(pOutputBuffer, pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength, TYPE_ALIGNMENT(char));
				DbgPrint("%i >= %i", pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength, dwDataSize);
				if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength >= dwDataSize)
				{
					/*
					* We use "RtlCopyMemory" in the kernel instead of memcpy.
					* RtlCopyMemory *IS* memcpy, however it's best to use the
					* wrapper in case this changes in the future.
					*/
					RtlCopyMemory(pOutputBuffer, pReturnData, dwDataSize);
					*pdwDataWritten = dwDataSize;
					NtStatus = STATUS_SUCCESS;
				}
				else
				{
					*pdwDataWritten = dwDataSize;
					NtStatus = STATUS_BUFFER_TOO_SMALL;
				}

			}


		}
		__except (EXCEPTION_EXECUTE_HANDLER) {

			NtStatus = GetExceptionCode();
		}

	}


	return NtStatus;
}


