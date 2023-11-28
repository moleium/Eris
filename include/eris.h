#ifndef ERIS_H
#define ERIS_H

#include <Windows.h>
#include <string>

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define nt_current_process ( (HANDLE)(LONG_PTR) -1 ) 

constexpr NTSTATUS k_status_info_length_mismatch = 0xC0000004;
constexpr BYTE k_process_handle_type = 0x7;
constexpr ULONG k_system_handle_information = 16;

typedef struct _unicode_string {
    USHORT length;
    USHORT maximum_length;
    PWCH   buffer;
} unicode_string, * punicode_string;

typedef struct _object_attributes {
    ULONG           length;
    HANDLE          root_directory;
    punicode_string object_name;
    ULONG           attributes;
    PVOID           security_descriptor;
    PVOID           security_quality_of_service;
}  object_attributes, * pobject_attributes;

typedef struct _client_id
{
    PVOID unique_process;
    PVOID unique_thread;
} client_id, * pclient_id;

typedef struct _system_handle_table_entry_info
{
    ULONG process_id;
    BYTE object_type_number;
    BYTE flags;
    USHORT handle;
    PVOID object;
    ACCESS_MASK granted_access;
} system_handle, * psystem_handle;

typedef struct _system_handle_information
{
    ULONG handle_count;
    system_handle handles[1];
} system_handle_information, * psystem_handle_information;

typedef NTSTATUS(NTAPI* _nt_duplicate_object)(
    HANDLE source_process_handle,
    HANDLE source_handle,
    HANDLE target_process_handle,
    PHANDLE target_handle,
    ACCESS_MASK desired_access,
    ULONG attributes,
    ULONG options
);

typedef NTSTATUS(NTAPI* _rtl_adjust_privilege)(
    ULONG privilege,
    BOOLEAN enable,
    BOOLEAN current_thread,
    PBOOLEAN enabled
);

typedef NTSTATUS(NTAPI* _nt_open_process)(
    PHANDLE            process_handle,
    ACCESS_MASK        desired_access,
    pobject_attributes object_attributes,
    pclient_id         client_id
);

typedef NTSTATUS(NTAPI* _nt_query_system_information)(
    ULONG system_information_class,
    PVOID system_information,
    ULONG system_information_length,
    PULONG return_length
);

typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(
    HANDLE process_handle,
    PVOID base_address,
    PVOID buffer,
    ULONG number_of_bytes_to_read,
    PULONG number_of_bytes_readed
);

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
    HANDLE process_handle,
    PVOID base_address,
    PVOID buffer,
    ULONG number_of_bytes_to_read,
    PULONG number_of_bytes_written
);

namespace eris {
    bool is_valid(HANDLE handle);
    DWORD get_pid(const std::string& process_name);
    HANDLE hijack(DWORD target_process_id, bool duplicate_handle);

    NTSTATUS read_vm(HANDLE process_handle, PVOID base_address, PVOID buffer, ULONG number_of_bytes_to_read);
    NTSTATUS write_vm(HANDLE process_handle, PVOID base_address, PVOID buffer, ULONG number_of_bytes_to_write);
}

#endif