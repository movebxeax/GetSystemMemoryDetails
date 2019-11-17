#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#include <memory>
#include <string>

#pragma pack(push)
#pragma pack(1)
typedef struct _RawSMBIOSData
{
	BYTE	Used20CallingMethod;
	BYTE	SMBIOSMajorVersion;
	BYTE	SMBIOSMinorVersion;
	BYTE	DmiRevision;
	DWORD	Length;
	PBYTE	SMBIOSTableData;
} RawSMBIOSData, *PRawSMBIOSData;

typedef struct _SMBIOSHEADER_
{
	BYTE Type;
	BYTE Length;
	WORD Handle;
} SMBIOSHEADER, *PSMBIOSHEADER;

typedef struct _TYPE_17_ {
	SMBIOSHEADER Header;
	UINT16	PhysicalArrayHandle;
	UINT16	ErrorInformationHandle;
	UINT16	TotalWidth;
	UINT16	DataWidth;
	UINT16	Size;
	UCHAR	FormFactor;
	UCHAR	DeviceSet;
	UCHAR	DeviceLocator;
	UCHAR	BankLocator;
	UCHAR	MemoryType;
	UINT16	TypeDetail;
	UINT16	Speed;
	UCHAR	Manufacturer;
	UCHAR	SN;
	UCHAR	AssetTag;
	UCHAR	PN;
	UCHAR	Attributes;
} MemoryDevice, *PMemoryDevice;

#pragma pack(pop) 

#define MEMORY_DEVICE_TYPE		17
#define END_OF_TABLE			127
#define SIGNATURE				'RSMB'

typedef UINT (WINAPI *GetSystemFirmwareTableT)(ULONG, ULONG, PVOID, ULONG);

char *ConvertToString(const char *str, UINT i)
{
	char *ptr = (char *)str;

	while(--i)
		ptr += strlen((char*)ptr) + 1;

	return ptr;
}

BOOL
GetSystemFirmwareTableWrapper()
{
	GetSystemFirmwareTableT get_systemfirmware_table = (GetSystemFirmwareTableT)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetSystemFirmwareTable");
	if(!get_systemfirmware_table)
		return FALSE;

	ULONG buffer_size = 0;

	buffer_size = get_systemfirmware_table(SIGNATURE, 0, NULL, 0);

	std::unique_ptr<char[]> buffer(new char[buffer_size]);
	ZeroMemory(buffer.get(), buffer_size);

	get_systemfirmware_table(SIGNATURE, 0, buffer.get(), buffer_size);

	const PRawSMBIOSData prsmbios_data = (PRawSMBIOSData)buffer.get();

	unsigned char *p = (unsigned char *)((PVOID)&prsmbios_data->SMBIOSTableData);

	const unsigned char *last_address = p + prsmbios_data->Length;
	PSMBIOSHEADER header;

	std::string data;

	for(;;)
	{
		header = (PSMBIOSHEADER)p;
		if(header->Type == MEMORY_DEVICE_TYPE)
		{
			PMemoryDevice md = (PMemoryDevice)p;
			const char *str = (char*)p + ((PSMBIOSHEADER)p)->Length;
			const char null_string[] = "Null";

			if(*str && md->PN)
			{
				data += ConvertToString(str, md->PN);
				data += "^";
				printf("parts # : %s\n", ConvertToString(str, md->PN));
			}

			if(*str && md->SN)
			{
				data += ConvertToString(str, md->SN);
				data += "|";
				printf("serial # : %s\n", ConvertToString(str, md->SN));
			}

			if(*str && md->Manufacturer)
			{
				data += ConvertToString(str, md->Manufacturer);
				data += "|";
				printf("Manufacturer : %s\n", ConvertToString(str, md->Manufacturer));
			}
		}

		if((header->Type == END_OF_TABLE) && (header->Length == 4))
			break;

		unsigned char *nt = p + header->Length;
		while(0 != (*nt | *(nt + 1)))
			++nt;

		nt += 2;
		if(nt >= last_address)
			break;

		p = nt;
	}
	return FALSE;
}

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
	SystemFirmwareTableEnumerate,
	SystemFirmwareTableGet,
	SystemFirmwareTableMax
} SYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
	ULONG ProviderSignature;
	SYSTEM_FIRMWARE_TABLE_ACTION Action;
	ULONG TableID;
	ULONG TableBufferLength;
	UCHAR TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;


#pragma comment(lib, "ntdll.lib")

bool NQSI_Smbios()
{
	typedef ULONG(WINAPI *NtQuerySystemInformationT)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG InformationLength, PULONG ResultLength);

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	NtQuerySystemInformationT nqsi = (NtQuerySystemInformationT)GetProcAddress(ntdll, "NtQuerySystemInformation");

	if(!nqsi)
		return FALSE;

	const ULONG nqsi_init_buf_size = 4096;
	PSYSTEM_FIRMWARE_TABLE_INFORMATION psfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nqsi_init_buf_size);

	psfti->Action = SystemFirmwareTableGet;
	psfti->ProviderSignature = SIGNATURE;
	psfti->TableID = 0;
	psfti->TableBufferLength = nqsi_init_buf_size;

	ULONG buffer_size = nqsi_init_buf_size;
	ULONG req_size;

	NTSTATUS ns;

	for(int i = 0; i < 20; i++)
	{
		ns = nqsi((SYSTEM_INFORMATION_CLASS)76, psfti, buffer_size, &req_size);
		if(NT_SUCCESS(ns))
			break;

		if(ns == STATUS_INVALID_INFO_CLASS
			|| ns == STATUS_INVALID_DEVICE_REQUEST
			|| ns == STATUS_NOT_IMPLEMENTED
			|| req_size == 0)
			break;

		if(ns == STATUS_INFO_LENGTH_MISMATCH)
		{
			buffer_size += req_size;
			HeapFree(GetProcessHeap(), 0, psfti);
			psfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, req_size);
		}
	}

	unsigned char *p = (unsigned char *)((PVOID)&psfti->TableBuffer);
	const unsigned char *last_address = p + psfti->TableBufferLength;
	PSMBIOSHEADER header;

	std::string data;

	for(;;)
	{
		header = (PSMBIOSHEADER)p;
		if(header->Type == MEMORY_DEVICE_TYPE)
		{
			PMemoryDevice md = (PMemoryDevice)p;
			const char *str = (char*)p + ((PSMBIOSHEADER)p)->Length;
			const char null_string[] = "Null";

			if(*str && md->PN)
			{
				data += ConvertToString(str, md->PN);
				data += "^";
				printf("parts # : %s\n", ConvertToString(str, md->PN));
			}

			if(*str && md->SN)
			{
				data += ConvertToString(str, md->SN);
				data += "|";
				printf("serial # : %s\n", ConvertToString(str, md->SN));
			}

			if(*str && md->Manufacturer)
			{
				data += ConvertToString(str, md->Manufacturer);
				data += "|";
				printf("Manufacturer : %s\n", ConvertToString(str, md->Manufacturer));
			}
		}

		if((header->Type == END_OF_TABLE) && (header->Length == 4))
			break;

		unsigned char *nt = p + header->Length;
		while(0 != (*nt | *(nt + 1)))
			++nt;

		nt += 2;
		if(nt >= last_address)
			break;

		p = nt;
	}

	HeapFree(GetProcessHeap(), 0, psfti);
}

int main()
{
	printf("nqsi\n");
	NQSI_Smbios();

	printf("gsft\n");
	GetSystemFirmwareTableWrapper();

	return 0;
}