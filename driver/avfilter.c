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

FLT_POSTOP_CALLBACK_STATUS
AvPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS AvConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                   PVOID ConnectionContext, ULONG SizeOfContext,
                   PVOID *ConnectionPortCookie);
VOID     AvDisconnect(PVOID ConnectionCookie);
NTSTATUS AvMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                   PVOID OutputBuffer, ULONG OutputBufferLength,
                   PULONG ReturnOutputBufferLength);

/* ---- Operation registration: we care about IRP_MJ_CREATE (file open) --- */

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, AvPostCreate },
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

FLT_POSTOP_CALLBACK_STATUS
AvPostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
             _In_ PCFLT_RELATED_OBJECTS FltObjects,
             _In_opt_ PVOID CompletionContext,
             _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    AV_SCAN_REQUEST request;
    AV_SCAN_REPLY  reply;
    ULONG replyLength = sizeof(reply);
    LARGE_INTEGER timeout;

    /* Skip directories, failed opens, draining, and the no-service case. */
    if (Flags & FLTFL_POST_OPERATION_DRAINING)            return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status))               return FLT_POSTOP_FINISHED_PROCESSING;
    if (Globals.ClientPort == NULL)                       return FLT_POSTOP_FINISHED_PROCESSING;
    if (PsGetCurrentProcessId() == Globals.ScannerPid)    return FLT_POSTOP_FINISHED_PROCESSING;

    if (FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_DIRECTORY_FILE)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Get the file name. */
    status = FltGetFileNameInformation(Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo);
    if (!NT_SUCCESS(status)) return FLT_POSTOP_FINISHED_PROCESSING;
    FltParseFileNameInformation(nameInfo);

    /* Build the scan request (truncate over-long paths for the skeleton). */
    RtlZeroMemory(&request, sizeof(request));
    request.PathLength = min(nameInfo->Name.Length, (AV_MAX_PATH - 1) * sizeof(WCHAR));
    RtlCopyMemory(request.Path, nameInfo->Name.Buffer, request.PathLength);

    /* Ask the user-mode service for a verdict, with a timeout so a hung
     * service can't deadlock file access forever.                         */
    timeout.QuadPart = -((LONGLONG)2 * 1000 * 1000 * 10); /* 2 seconds; fail open */
    status = FltSendMessage(Globals.Filter, &Globals.ClientPort,
                            &request, sizeof(request),
                            &reply, &replyLength, &timeout);

    if (status == STATUS_SUCCESS && reply.Infected) {
        /* Block the open: tear down access and report infection. */
        Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
        Data->IoStatus.Information = 0;
        FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
