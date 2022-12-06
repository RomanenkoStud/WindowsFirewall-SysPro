#include "framework.h"
#include "UDriver.h"

UDriver::UDriver(void)
{
	driverHandle = NULL;

	removable = TRUE;

	initialized = FALSE;
	loaded = FALSE;
	started = FALSE;
}

UDriver::~UDriver(void)
{
	if (driverHandle != NULL)
	{
		CloseHandle(driverHandle);
		driverHandle = NULL;
	}

	UnloadDriver();
}

void UDriver::SetRemovable(BOOL value)
{
	removable = value;
}

BOOL UDriver::IsInitialized(void)
{
	return initialized;
}

BOOL UDriver::IsLoaded(void)
{
	return loaded;
}

BOOL UDriver::IsStarted(void)
{
	return started;
}

DWORD UDriver::InitDriver(LPCTSTR path)
{
	//if already initialized, first unload
	if (initialized)
	{
		if (UnloadDriver() != DRV_SUCCESS)
			return DRV_ERROR_ALREADY_INITIALIZED;
	}

	
	driverPath = path;

	driverName = L"Firewall";

	//driverDosName = \\.\driverName 
	driverDosName += L"\\\\.\\";
	driverDosName += driverName;


	initialized = TRUE;
	return DRV_SUCCESS;
}

DWORD UDriver::InitDriver(LPCTSTR name, LPCTSTR path, LPCTSTR dosName)
{
	//if already initialized, first unload
	if (initialized)
	{
		if (UnloadDriver() != DRV_SUCCESS)
			return DRV_ERROR_ALREADY_INITIALIZED;
	}

	//if the user introduced path
	if (path != NULL)
	{
		//if yes, copy in auxiliar buffer and continue
		driverPath = path;
	}

	else
	{
		WCHAR Buffer[100];
		GetCurrentDirectory(100, Buffer);
		driverPath += std::wstring(Buffer);
		//if the user dont introduced name
		if (name == NULL)
		{
			return DRV_ERROR_UNKNOWN;
		}
		driverPath += L'\\';
		driverPath += name;
		driverPath += L".sys";

		if (GetFileAttributes(driverPath.c_str()) == 0xFFFFFFFF)
		{
			return DRV_ERROR_INVALID_PATH_OR_FILE;
		}
	}

	driverName = name;

	//dosName=\\.\driverName
	driverDosName += L"\\\\.\\";
	driverDosName += driverName;

	//set the state to initialized
	initialized = TRUE;

	return DRV_SUCCESS;
}

DWORD UDriver::LoadDriver(LPCTSTR name, LPCTSTR path, LPCTSTR dosName, BOOL start)
{
	//first initialized it
	DWORD retCode = InitDriver(name, path, dosName);

	//then load
	if (retCode == DRV_SUCCESS)
		retCode = LoadDriver(start);

	return retCode;
}

DWORD UDriver::LoadDriver(LPCTSTR path, BOOL start)
{
	//first initialized it
	DWORD retCode = InitDriver(path);

	//then load
	if (retCode == DRV_SUCCESS)
		retCode = LoadDriver(start);

	return retCode;
}

DWORD UDriver::LoadDriver(BOOL start)
{
	//if the driver is already started, i havent to do nothing
	if (loaded)
		return DRV_SUCCESS;

	if (!initialized)
		return DRV_ERROR_NO_INITIALIZED;

	//Open Service manager to create the new "service"
	SC_HANDLE SCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	DWORD retCode = DRV_SUCCESS;

	if (SCManager == NULL)
		return DRV_ERROR_SCM;



	//Create the driver "service"
	SC_HANDLE  SCService = CreateServiceW(SCManager,			  // SCManager database
		driverName.c_str(),            // nombre del servicio
		driverName.c_str(),            // nombre a mostrar
		SERVICE_ALL_ACCESS,    // acceso total
		SERVICE_KERNEL_DRIVER, // driver del kernel
		SERVICE_DEMAND_START,  // comienzo bajo demanda
		SERVICE_ERROR_NORMAL,  // control de errores normal
		driverPath.c_str(),	          // path del driver
		NULL,                  // no pertenece a un grupo
		NULL,                  // sin tag
		NULL,                  // sin dependencias
		NULL,                  // cuenta local del sistema
		NULL                   // sin password
	);

	//if i cant create, first i check if the driver already was loaded.
	if (SCService == NULL)
	{
		SCService = OpenServiceW(SCManager, driverName.c_str(), SERVICE_ALL_ACCESS);

		if (SCService == NULL)
			retCode = DRV_ERROR_SERVICE;
	}

	CloseServiceHandle(SCService);
	SCService = NULL;

	CloseServiceHandle(SCManager);
	SCManager = NULL;

	//if all ok, update the state and start if necessary
	if (retCode == DRV_SUCCESS)
	{
		loaded = TRUE;

		if (start)
			retCode = StartDriver();
	}

	return retCode;
}

DWORD UDriver::UnloadDriver(BOOL forceClearData)
{
	DWORD retCode = DRV_SUCCESS;

	//if the driver is started, first i will stop it
	if (started)
	{
		if ((retCode = StopDriver()) == DRV_SUCCESS)
		{
			//i only remove it, if it is mark to be removable
			if (removable)
			{
				//open service and delete it
				SC_HANDLE SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

				if (SCManager == NULL)
					return DRV_ERROR_SCM;

				SC_HANDLE SCService = OpenServiceW(SCManager, driverName.c_str(), SERVICE_ALL_ACCESS);

				if (SCService != NULL)
				{
					if (!DeleteService(SCService))
						retCode = DRV_ERROR_REMOVING;
					else
						retCode = DRV_SUCCESS;
				}

				else
					retCode = DRV_ERROR_SERVICE;

				CloseServiceHandle(SCService);
				SCService = NULL;

				CloseServiceHandle(SCManager);
				SCManager = NULL;

				//if all ok, update the state
				if (retCode == DRV_SUCCESS)
					loaded = FALSE;
			}
		}
	}

	//if the driver is initialized...
	if (initialized)
	{
		//if there was some problem but i mark foreceClear, i will remove the data
		if (retCode != DRV_SUCCESS && forceClearData == FALSE)
			return retCode;

		//update the state
		initialized = FALSE;

		//free memory
		driverPath.clear();
		driverDosName.clear();
		driverName.clear();

	}

	return retCode;
}

DWORD UDriver::StartDriver(void)
{
	//if already started, all ok
	if (started)
		return DRV_SUCCESS;

	//open the service manager and the service and change driver state
	SC_HANDLE SCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	DWORD retCode;

	if (SCManager == NULL)
		return DRV_ERROR_SCM;

	SC_HANDLE SCService = OpenServiceW(SCManager,
		driverName.c_str(),
		SERVICE_ALL_ACCESS);

	if (SCService == NULL)
		return DRV_ERROR_SERVICE;


	if (!StartServiceW(SCService, 0, NULL))
	{
		//if the driver was started before i try to do it,
		//i will not remove, because it was created by other application
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
		{
			removable = FALSE;

			retCode = DRV_SUCCESS;
		}

		else
			retCode = DRV_ERROR_STARTING;
	}

	else
		retCode = DRV_SUCCESS;


	CloseServiceHandle(SCService);
	SCService = NULL;

	CloseServiceHandle(SCManager);
	SCManager = NULL;

	//update the state and open device
	if (retCode == DRV_SUCCESS)
	{
		started = TRUE;

		retCode = OpenDevice();
	}

	return retCode;
}

DWORD UDriver::StopDriver(void)
{
	//if already stopped, all ok
	if (!started)
		return DRV_SUCCESS;

	//open the service manager and the service and change driver state
	SC_HANDLE SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	DWORD retCode;

	if (SCManager == NULL)
		return DRV_ERROR_SCM;


	SERVICE_STATUS  status;

	SC_HANDLE SCService = OpenServiceW(SCManager, driverName.c_str(), SERVICE_ALL_ACCESS);

	if (SCService != NULL)
	{
		//close the driver handle too
		CloseHandle(driverHandle);
		driverHandle = NULL;

		if (!ControlService(SCService, SERVICE_CONTROL_STOP, &status))
			retCode = DRV_ERROR_STOPPING;

		else
			retCode = DRV_SUCCESS;
	}

	else
		retCode = DRV_ERROR_SERVICE;


	CloseServiceHandle(SCService);
	SCService = NULL;

	CloseServiceHandle(SCManager);
	SCManager = NULL;

	//update the state
	if (retCode == DRV_SUCCESS)
		started = FALSE;

	return retCode;
}

DWORD UDriver::OpenDevice(void)
{
	//if i already have a handle, first close it
	if (driverHandle != NULL)
		CloseHandle(driverHandle);

	driverHandle = CreateFileW(driverDosName.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	if (driverHandle == INVALID_HANDLE_VALUE)
		return DRV_ERROR_INVALID_HANDLE;

	return DRV_SUCCESS;
}

HANDLE UDriver::GetDriverHandle(void)
{
	return driverHandle;
}

DWORD UDriver::WriteIo(DWORD code, PVOID buffer, DWORD count)
{
	if (driverHandle == NULL)
		return DRV_ERROR_INVALID_HANDLE;

	DWORD bytesReturned;

	BOOL returnCode = DeviceIoControl(driverHandle,
		code,
		buffer,
		count,
		NULL,
		0,
		&bytesReturned,
		NULL);

	if (!returnCode)
		return DRV_ERROR_IO;

	return DRV_SUCCESS;
}

DWORD UDriver::ReadIo(DWORD code, PVOID buffer, DWORD count)
{
	if (driverHandle == NULL)
		return DRV_ERROR_INVALID_HANDLE;

	DWORD bytesReturned;
	BOOL retCode = DeviceIoControl(driverHandle,
		code,
		NULL,
		0,
		buffer,
		count,
		&bytesReturned,
		NULL);

	if (!retCode)
		return DRV_ERROR_IO;

	return bytesReturned;
}

DWORD UDriver::RawIo(DWORD code, PVOID inBuffer, DWORD inCount, PVOID outBuffer, DWORD outCount)
{
	if (driverHandle == NULL)
		return DRV_ERROR_INVALID_HANDLE;

	DWORD bytesReturned;
	BOOL retCode = DeviceIoControl(driverHandle,
		code,
		inBuffer,
		inCount,
		outBuffer,
		outCount,
		&bytesReturned,
		NULL);

	if (!retCode)
		return DRV_ERROR_IO;

	return bytesReturned;
}