/**********************************************************************
*
*  Toby Opferman
*
*  Driver PH
*
*  This PH is for educational purposes only.  I license this source
*  out for use in learning how to write a device driver.
*
*     Driver Shared Header File
**********************************************************************/
int _myStatus;
PWCHAR _myHookedProcessName;
unsigned long *_myHookedProcessID;
HANDLE _myHookedProcessHandle;
HANDLE _myLogFileHandle;

NTSTATUS ZwQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG); // Used to get the process name.
//[DllImport("kernel32.dll")]
//unsigned int ResumeThread(HANDLE hThread);

#ifndef __PH_H__
#define __PH_H__

typedef unsigned int UINT;
typedef char * PCHAR; 

#define  MAX_LINE 1024

 /*#define __USE_DIRECT__ 
 #define __USE_BUFFERED__ */

//NTSTATUS PH_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS PH_Close(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS PH_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS PH_WriteBufferedIO(PDEVICE_OBJECT DeviceObject, PIRP Irp);/
//NTSTATUS PH_WriteDirectIO(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS PH_WriteNeither(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS PH_ReadBufferedIO(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS PH_ReadDirectIO(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS PH_ReadNeither(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS PH_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS _logging(PWCHAR _buffer);

#ifdef __USE_DIRECT__
#define IO_TYPE DO_DIRECT_IO
#define USE_WRITE_FUNCTION  PH_WriteDirectIO
#define USE_READ_FUNCTION   PH_ReadDirectIO
#endif

#ifdef __USE_BUFFERED__
#define IO_TYPE DO_BUFFERED_IO
#define USE_WRITE_FUNCTION  PH_WriteBufferedIO
#define USE_READ_FUNCTION   PH_ReadBufferedIO
#endif

#ifndef IO_TYPE
#define IO_TYPE 0
#define USE_WRITE_FUNCTION  PH_WriteNeither
#define USE_READ_FUNCTION   PH_ReadNeither
#endif

#endif




