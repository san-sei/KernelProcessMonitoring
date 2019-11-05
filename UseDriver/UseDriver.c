/**********************************************************************
*
*  Toby Opferman
*
*  PH Dynamic Loading a Driver
*
*  This PH is for educational purposes only.  I license this source
*  out for use in learning how to write a device driver.
*
*
**********************************************************************/


#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <WINIOCTL.H>
#include "IOCTLWin.h"
#include <stdlib.h>

int _UsingDriver();
int _EndOfUsingDriver();
int __stdcall DoStartSvc(char * szSvcName, PHANDLE schSCManager1, PHANDLE schService);

/*********************************************************
*   Main Function Entry
*
*********************************************************/
int _cdecl main(int argc, char* argv[])
{
	//
	//...check exsisting file
	//
	char _path[MAX_PATH] = { 0 };
	FILE *hfile;
	if (argc > 1 && !fopen_s(&hfile, argv[1], "r"))
	{
		printf("file %s exsist.\n", argv[1]);
		if (!fclose(hfile))
		{
			printf("file closed.\n");
		}
		else
		{
			printf("file not closed closed.\n");
		}
		strcpy_s(_path, MAX_PATH, argv[1]);
	}
	else if (argc == 1)
	{
		strcpy_s(_path, MAX_PATH, "C:\\windows\\system32\\notepad.exe");
	}
	else
	{
		printf("file %s dose not exsist.\n", argv[1]);
		return 0;
	}
	printf("filename is [%s]\n", _path);
	printf("press any key to continue if everything is okay...\n");
	getchar();
	//
	//goes to Create Servise and making it ready to use
	//

	HANDLE hSCManager;
	HANDLE hService;
//	SERVICE_STATUS ss;
	int _Startflag = 0;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return 0;
	}
	printf("Load Driver\n");

	printf("Create Service..........................\n");
	hService = CreateService(hSCManager, "ProcessHooking", "ProcessHooking Driver", SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, "C:\\ProcessHooking.sys", NULL, NULL, NULL, NULL, NULL);
	printf("%d\n", hService);
	if (hService && !StartService(hService, 0, NULL))
	{
		_Startflag = 1;
	}
	else if (DoStartSvc("ProcessHooking", &hSCManager, &hService))
	{
		_Startflag = 1;
	}
	if (_Startflag)
	{
		printf("Start Service\n");
		HANDLE _hProcess = 0;
		int _retValue = 0;
		_retValue = _UsingDriver(&_hProcess, _path);

		printf("Press Enter to close service...\n");
		getchar();
		_EndOfUsingDriver();
		/*int _s1 = ControlService(hService, SERVICE_CONTROL_STOP, &ss);
		printf("after ControlService '%d'", _s1);
		getchar();
		int _s2 = CloseServiceHandle(hService);
		printf("after CloseServiceHandle '%d'", _s2);
		getchar();
		int _s3 = DeleteService(hService);
		printf("after DeleteService '%d'", _s3);
		getchar();*/
		if (_retValue)
		{
			__try{
				printf("goes to try for terminating process. returned [%d]\n", TerminateProcess(_hProcess, 1));
			}
			__except (EXCEPTION_EXECUTE_HANDLER){
				printf("Raise an error in terminating process.\n");
			}
		}
	}
	CloseServiceHandle(hSCManager);

	printf("GoodLuck!");
	getchar();
	return 0;
}

int _UsingDriver(PHANDLE _hProcess, char *_path)
{
	int returnvalue = 0;
	HANDLE hFile;
	DWORD dwReturn = 1;
	char szTemp[512] = { 0 };

	hFile = CreateFile("\\\\.\\ProcessHooking", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile)
	{
		STARTUPINFO             startupInfo;
		PROCESS_INFORMATION     processInformation;

		memset(&startupInfo, 0, sizeof(startupInfo));
		startupInfo.cb = sizeof(STARTUPINFO);

		if (CreateProcess(
			_path,
			NULL,
			NULL,
			NULL,
			FALSE,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&startupInfo,
			&processInformation))
		{
			returnvalue = 1;
			*_hProcess = processInformation.hProcess;
			//
			printf("Process created in a suspended state.\n");
			//
			char _myHandles[1024] = { 0 };
			char _myTemp[512] = { 0 };
			_itoa_s((int)processInformation.hProcess, _myHandles, 1024, 10);
			strcat_s(_myHandles, 1024, ",");
			_itoa_s((int)processInformation.hThread, _myTemp, 512, 10);
			strcat_s(_myHandles, 1024, _myTemp);
			RtlZeroMemory(_myTemp, 512);
			_itoa_s(processInformation.dwProcessId, _myTemp, 512, 10);
			strcat_s(_myHandles, 1024, ",");
			strcat_s(_myHandles, 1024, _myTemp);
			//
			ZeroMemory(szTemp, sizeof(szTemp));
			printf("_myhandles is [%s]\n", _myHandles);
			DeviceIoControl(hFile, IOCTL_PH_SAMPLE_BUFFERED_IO, _myHandles, sizeof(_myHandles), szTemp, sizeof(szTemp), &dwReturn, NULL);
			printf("resived message from kernel land is [%s,%d]\n", szTemp, dwReturn);
			if (dwReturn >= 1)
			{
				printf("process goes to running............\n");
				ResumeThread(processInformation.hThread);
			}
			else
			{
				printf("not recive any command from kernel land for resuming process.\n");
			}
		}
		else
		{
			printf("cann't create process, somethings gose wrong.\n");
			returnvalue = 0;
			//
		}
		CloseHandle(hFile);
	}
	else
	{
		returnvalue = 0;
		printf("No Service found here.\n");
	}
	return returnvalue;
}

int _EndOfUsingDriver()
{
	int returnvalue = 0;
	HANDLE hFile;
	DWORD dwReturn = 1;
	char _inputBuffer[512] = { 0 };
	char _outputBuffer[512] = { 0 };

	hFile = CreateFile("\\\\.\\ProcessHooking", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile)
	{
		strcpy_s(_inputBuffer, 512, "#ok#");
		DeviceIoControl(hFile, IOCTL_PH_SAMPLE_BUFFERED_IO, _inputBuffer, sizeof(_inputBuffer), _outputBuffer, sizeof(_outputBuffer), &dwReturn, NULL);
		printf("resived message from kernel land is [%s,%d]\n", _outputBuffer, dwReturn);
		if (dwReturn >= 1)
		{
			returnvalue = 1;
			printf("goes to closing everything in driver...\n");
		}
		else
		{
			printf("not recive any command from kernel land for resuming process.\n");
		}
		CloseHandle(hFile);
	}
	else
	{
		returnvalue = 0;
		printf("No Service found here.\n");
	}
	return returnvalue;
}
//
// Purpose: 
//   Starts the service if possible.
//
// Parameters:
//   None
// 
// Return value:
//   None
//
int __stdcall DoStartSvc(char * szSvcName, PHANDLE schSCManager1, PHANDLE schService1)
{
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwOldCheckPoint;
	DWORD dwStartTickCount;
	DWORD dwWaitTime;
	DWORD dwBytesNeeded;

	// Get a handle to the SCM database. 
	HANDLE schSCManager;
	HANDLE schService;
	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // servicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return 0;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,         // SCM database 
		szSvcName,            // name of service 
		SERVICE_ALL_ACCESS);  // full access 

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return 0;
	}

	// Check the status in case the service is not stopped. 

	if (!QueryServiceStatusEx(
		schService,                     // handle to service 
		SC_STATUS_PROCESS_INFO,         // information level
		(LPBYTE)&ssStatus,             // address of structure
		sizeof(SERVICE_STATUS_PROCESS), // size of structure
		&dwBytesNeeded))              // size needed if buffer is too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return 0;
	}

	// Check if the service is already running. It would be possible 
	// to stop the service here, but for simplicity this example just returns. 

	if (ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
	{
		printf("Cannot start the service because it is already running\n");
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return 1;
	}

	// Save the tick count and initial checkpoint.

	dwStartTickCount = GetTickCount();
	dwOldCheckPoint = ssStatus.dwCheckPoint;

	// Wait for the service to stop before attempting to start it.

	while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth of the wait hint but not less than 1 second  
		// and not more than 10 seconds. 

		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status until the service is no longer stop pending. 

		if (!QueryServiceStatusEx(
			schService,                     // handle to service 
			SC_STATUS_PROCESS_INFO,         // information level
			(LPBYTE)&ssStatus,             // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))              // size needed if buffer is too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return 0;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.

			dwStartTickCount = GetTickCount();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				printf("Timeout waiting for service to stop\n");
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return 0;
			}
		}
	}

	// Attempt to start the service.

	if (!StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))      // no arguments 
	{
		printf("StartService failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return 0;
	}
	else printf("Service start pending...\n");

	// Check the status until the service is no longer start pending. 

	if (!QueryServiceStatusEx(
		schService,                     // handle to service 
		SC_STATUS_PROCESS_INFO,         // info level
		(LPBYTE)&ssStatus,             // address of structure
		sizeof(SERVICE_STATUS_PROCESS), // size of structure
		&dwBytesNeeded))              // if buffer too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return 0;
	}

	// Save the tick count and initial checkpoint.

	dwStartTickCount = GetTickCount();
	dwOldCheckPoint = ssStatus.dwCheckPoint;

	while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth the wait hint, but no less than 1 second and no 
		// more than 10 seconds. 

		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status again. 

		if (!QueryServiceStatusEx(
			schService,             // handle to service 
			SC_STATUS_PROCESS_INFO, // info level
			(LPBYTE)&ssStatus,             // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))              // if buffer too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			break;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.

			dwStartTickCount = GetTickCount();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				// No progress made within the wait hint.
				break;
			}
		}
	}

	// Determine whether the service is running.
	if (ssStatus.dwCurrentState == SERVICE_RUNNING)
	{
		printf("Service started successfully.\n");
		*schSCManager1 = schSCManager;
		*schService1 = schService;
		return 1;
	}
	else
	{
		printf("Service not started. \n");
		printf("  Current State: %d\n", ssStatus.dwCurrentState);
		printf("  Exit Code: %d\n", ssStatus.dwWin32ExitCode);
		printf("  Check Point: %d\n", ssStatus.dwCheckPoint);
		printf("  Wait Hint: %d\n", ssStatus.dwWaitHint);
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return 0;
}