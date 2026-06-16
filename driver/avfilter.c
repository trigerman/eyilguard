/*
 * avfilter.c — educational file-system minifilter for on-access scanning.
 *
 * Architecture: this kernel driver intercepts file opens, sends the path
 * up to a user-mode service over a filter communication port, waits for a
 * verdict, and blocks access if the service reports the file is infected.
 *
 * Build with the Windows Driver Kit (WDK) as a "Filter Driver: Filesystem
 * Mini-Filter" project. This is a SKELETON: error paths are simplified and
 * several production concerns (re-entrancy, cancellation, performance) are
 * left as TODOs.
 *
 * Based on the public Microsoft "scanner" minifilter sample pattern.
 */

#include <fltKernel.h>
#include <dontuse.h>

#include "avscan_protocol.h"

#define AV_SCAN_SCOPE L"\\EyilScanLab\\"
#define AV_EICAR_TEST_NAME L"\\eyil-eicar.com"

/* ---- Global filter state ---------------------------------------------- */

typedef struct _AV_GLOBALS {
    PFLT_FILTER Filter;                /* our registered filter handle     */
    PFLT_PORT   ServerPort;            /* port the service connects to     */
    PFLT_PORT   ClientPort;            /* the connected service's port     */
    HANDLE      ScannerPid;            /* PID of connected scanner service */
} AV_GLOBALS;

AV_GLOBALS Globals;

/* ---- Forward declarations --------------------------------------------- */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS AvUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
AvPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
);

NTSTATUS AvConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                   PVOID ConnectionContext, ULONG SizeOfContext,
                   PVOID *ConnectionPortCookie);
VOID     AvDisconnect(PVOID ConnectionCookie);
NTSTATUS AvMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                   PVOID OutputBuffer, ULONG OutputBufferLength,
                   PULONG ReturnOutputBufferLength);

static BOOLEAN
AvPathInScanScope(_In_ PUNICODE_STRING Path)
{
    UNICODE_STRING scope;
    USHORT offset;

    RtlInitUnicodeString(&scope, AV_SCAN_SCOPE);
    if (Path->Length < scope.Length) {
        return FALSE;
    }

    for (offset = 0; offset <= Path->Length - scope.Length; offset += sizeof(WCHAR)) {
        UNICODE_STRING candidate;
        candidate.Buffer = (PWCHAR)((PUCHAR)Path->Buffer + offset);
        candidate.Length = scope.Length;
        candidate.MaximumLength = scope.Length;
        if (RtlCompareUnicodeString(&candidate, &scope, TRUE) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
AvPathContains(_In_ PUNICODE_STRING Path, _In_z_ PCWSTR Needle)
{
    UNICODE_STRING needle;
    USHORT offset;

    RtlInitUnicodeString(&needle, Needle);
    if (Path->Length < needle.Length) {
        return FALSE;
    }

    for (offset = 0; offset <= Path->Length - needle.Length; offset += sizeof(WCHAR)) {
        UNICODE_STRING candidate;
        candidate.Buffer = (PWCHAR)((PUCHAR)Path->Buffer + offset);
        candidate.Length = needle.Length;
        candidate.MaximumLength = needle.Length;
        if (RtlCompareUnicodeString(&candidate, &needle, TRUE) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

/* ---- Operation registration: we care about IRP_MJ_CREATE (file open) --- */

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, AvPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),          /* Size                            */
    FLT_REGISTRATION_VERSION,          /* Version                         */
    0,                                 /* Flags                           */
    NULL,                              /* ContextRegistration             */
    Callbacks,                         /* OperationCallbacks              */
    AvUnload,                          /* FilterUnloadCallback            */
    NULL,                              /* InstanceSetupCallback           */
    NULL,                              /* InstanceQueryTeardownCallback   */
    NULL,                              /* InstanceTeardownStartCallback   */
    NULL,                              /* InstanceTeardownCompleteCallback*/
    NULL, NULL, NULL, NULL, NULL       /* name provider callbacks (unused)*/
};

/* ---- DriverEntry ------------------------------------------------------- */

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    RtlZeroMemory(&Globals, sizeof(Globals));

    /* 1. Register as a minifilter. */
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &Globals.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 2. Create the communication port the user-mode service connects to.
     *    The security descriptor restricts the port to admins by default. */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        goto cleanup_filter;
    }

    RtlInitUnicodeString(&portName, AV_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, sd);

    status = FltCreateCommunicationPort(Globals.Filter, &Globals.ServerPort,
                                        &oa, NULL,
                                        AvConnect, AvDisconnect, AvMessage,
                                        1 /* max one connected service */);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status)) {
        goto cleanup_filter;
    }

    /* 3. Begin filtering I/O. */
    status = FltStartFiltering(Globals.Filter);
    if (!NT_SUCCESS(status)) {
        goto cleanup_port;
    }

    return STATUS_SUCCESS;

cleanup_port:
    FltCloseCommunicationPort(Globals.ServerPort);
cleanup_filter:
    FltUnregisterFilter(Globals.Filter);
    return status;
}

NTSTATUS
AvUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (Globals.ServerPort) FltCloseCommunicationPort(Globals.ServerPort);
    if (Globals.Filter)     FltUnregisterFilter(Globals.Filter);
    return STATUS_SUCCESS;
}

/* ---- Comm-port connection bookkeeping ---------------------------------- */

NTSTATUS
AvConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
          PVOID ConnectionContext, ULONG SizeOfContext,
          PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    Globals.ClientPort = ClientPort;   /* remember who to ask for verdicts */
    Globals.ScannerPid = PsGetCurrentProcessId();
    return STATUS_SUCCESS;
}

VOID
AvDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(Globals.Filter, &Globals.ClientPort);
    Globals.ClientPort = NULL;
    Globals.ScannerPid = NULL;
}

NTSTATUS
AvMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
          PVOID OutputBuffer, ULONG OutputBufferLength,
          PULONG ReturnOutputBufferLength)
{
    /* The service can push messages to the driver here if you want a
     * two-way control channel. Not needed for basic scanning. */
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
}

/* ---- The heart of it: scan-on-open ------------------------------------- */

FLT_PREOP_CALLBACK_STATUS
AvPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
            _In_ PCFLT_RELATED_OBJECTS FltObjects,
            _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PAV_SCAN_REQUEST request = NULL;
    AV_SCAN_REPLY  reply;
    ULONG replyLength = sizeof(reply);
    LARGE_INTEGER timeout;

    *CompletionContext = NULL;

    /* Skip directories, failed opens, draining, and the no-service case. */
    if (Globals.ClientPort == NULL)                       return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (PsGetCurrentProcessId() == Globals.ScannerPid)    return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Get the file name. */
    status = FltGetFileNameInformation(Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    FltParseFileNameInformation(nameInfo);
    if (!AvPathInScanScope(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (AvPathContains(&nameInfo->Name, AV_EICAR_TEST_NAME)) {
        Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
        Data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    /* Build the scan request (truncate over-long paths for the skeleton). */
    request = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*request), 'rqvA');
    if (request == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(request, sizeof(*request));
    request->PathLength = min(nameInfo->Name.Length, (AV_MAX_PATH - 1) * sizeof(WCHAR));
    RtlCopyMemory(request->Path, nameInfo->Name.Buffer, request->PathLength);

    /* Ask the user-mode service for a verdict, with a timeout so a hung
     * service can't deadlock file access forever.                         */
    timeout.QuadPart = -((LONGLONG)2 * 1000 * 1000 * 10); /* 2 seconds; fail open */
    status = FltSendMessage(Globals.Filter, &Globals.ClientPort,
                            request, sizeof(*request),
                            &reply, &replyLength, &timeout);

    if (status == STATUS_SUCCESS && reply.Infected) {
        /* Block the open before the file object is handed to the caller. */
        Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
        Data->IoStatus.Information = 0;
        ExFreePoolWithTag(request, 'rqvA');
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    ExFreePoolWithTag(request, 'rqvA');
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
