/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"

#pragma NDIS_INIT_FUNCTION(ndislwf1RegisterDevice)


_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
ndislwf1RegisterDevice(
    VOID
    )
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
    PDRIVER_OBJECT                  DriverObject;
   
    DEBUGP(DL_TRACE, "==>ndislwf1RegisterDevice\n");
   
    
    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));
    
    DispatchTable[IRP_MJ_CREATE] = ndislwf1Dispatch;
    DispatchTable[IRP_MJ_CLEANUP] = ndislwf1Dispatch;
    DispatchTable[IRP_MJ_CLOSE] = ndislwf1Dispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = ndislwf1DeviceIoControl;
    
    
    NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);
    
    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));
    
    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);
    
    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);
    
    Status = NdisRegisterDeviceEx(
                FilterDriverHandle,
                &DeviceAttribute,
                &NdisDeviceObject,
                &NdisFilterDeviceHandle
                );
   
   
    if (Status == NDIS_STATUS_SUCCESS)
    {
        FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION) NdisGetDeviceReservedExtension(NdisDeviceObject);
   
        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;

        //
        // Workaround NDIS bug
        //
        DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
    }
              
        
    DEBUGP(DL_TRACE, "<==ndislwf1RegisterDevice: %x\n", Status);
        
    return (Status);
        
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ndislwf1DeregisterDevice(
    VOID
    )

{
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

_Use_decl_annotations_
NTSTATUS
ndislwf1Dispatch(
    PDEVICE_OBJECT       DeviceObject,
    PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    
    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;

        case IRP_MJ_CLEANUP:
            break;

        case IRP_MJ_CLOSE:
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

_Use_decl_annotations_                
NTSTATUS
ndislwf1DeviceIoControl(
    PDEVICE_OBJECT        DeviceObject,
    PIRP                  Irp
    )
{
    PIO_STACK_LOCATION          IrpSp;
    NTSTATUS                    Status = STATUS_SUCCESS;
    PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;
    PUCHAR                      InputBuffer;
    PUCHAR                      OutputBuffer;
    ULONG                       InputBufferLength, OutputBufferLength;
    PLIST_ENTRY                 Link;
    PUCHAR                      pInfo;
    SIZE_T                       InfoLength = 0;
    PMS_FILTER                  pFilter = NULL;
    BOOLEAN                     bFalse = FALSE;

	// FW stuff
	char* data = 0;
	SECURITY_SUBJECT_CONTEXT ssc = { 0 };
	BOOLEAN isAdmin = FALSE;
	void* integrity = 0;

	size_t struct_size = (size_t)-1;
	char* policy = (char*)-1;
	void* fw = 0;


    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
	
    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }

    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');
    
    Irp->IoStatus.Information = 0;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {

        case IOCTL_FILTER_RESTART_ALL:
            break;

        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);

            if (pFilter == NULL)
            {
                
                break;
            }

            NdisFRestartFilter(pFilter->FilterHandle);

            break;

        case IOCTL_FILTER_ENUERATE_ALL_INSTANCES:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            
            
            pInfo = OutputBuffer;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

                
                InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                        
                if (InfoLength <= OutputBufferLength)
                {
                    *(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
                    NdisMoveMemory(pInfo + sizeof(USHORT), 
                                   (PUCHAR)(pFilter->FilterModuleName.Buffer),
                                   pFilter->FilterModuleName.Length);
                            
                    pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                }
                
                Link = Link->Flink;
            }
               
            FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
            if (InfoLength <= OutputBufferLength)
            {
       
                Status = NDIS_STATUS_SUCCESS;
            }
            //
            // Buffer is small
            //
            else
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

		case IOCTL_FILTER_FW_UPDATE_POLICY:
			
			//DbgBreakPoint();
			data = Irp->AssociatedIrp.SystemBuffer;

			SeCaptureSubjectContext(&ssc);
			isAdmin = SeTokenIsAdmin(ssc.PrimaryToken);
			Status = SeQueryInformationToken(ssc.PrimaryToken, TokenIntegrityLevel, &integrity);

			if (isAdmin && ((long long)integrity == SECURITY_MANDATORY_HIGH_RID || (long long)integrity == SECURITY_MANDATORY_SYSTEM_RID) && data)
			{

				
				//DbgPrint("admin and integrity\n");
				Status = UpdateFWRules(data);
			}
			else
			{
				Status = STATUS_ACCESS_DENIED;
			}			
			
			break;
             
		case IOCTL_FILTER_FW_SHOW_POLICY:
			/*
			 Calculate fw struct size
			 if input size bigger or equal
				return fw struct
			 else
				return status = STATUS_BUFFER_TOO_SMALL and fw struct size
			*/
			//DbgBreakPoint();

			SeCaptureSubjectContext(&ssc);
			isAdmin = SeTokenIsAdmin(ssc.PrimaryToken);
			Status = SeQueryInformationToken(ssc.PrimaryToken, TokenIntegrityLevel, &integrity);

			if ((isAdmin && ((long long)integrity == SECURITY_MANDATORY_HIGH_RID || (long long)integrity == SECURITY_MANDATORY_SYSTEM_RID)) == FALSE)
			{
				Status = STATUS_ACCESS_DENIED;
				break;
			}

			policy = Irp->AssociatedIrp.SystemBuffer;

			struct_size = GetFwSize(*policy);

			if (struct_size <= IrpSp->Parameters.DeviceIoControl.OutputBufferLength)
			{

				if (*policy == FWPolicy_Incoming)
				{
					fw = GetIncomingFW();
				}
				else if (*policy == FWPolicy_Outgoing)
				{
					fw = GetOutgoingFW();
				}
				else
				{
					break;
				}

				memcpy(Irp->AssociatedIrp.SystemBuffer, fw, struct_size);
				InfoLength = struct_size;
			}
			else if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength == 4)
			{
				//Status = STATUS_BUFFER_TOO_SMALL;
				memcpy(Irp->AssociatedIrp.SystemBuffer, &struct_size, 4);
				InfoLength = 4;
			}
			else
			{
				Status = STATUS_BUFFER_TOO_SMALL;
			}
			
			break;
        default:
            break;
    }
	
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = InfoLength;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
            

}


_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
    _In_reads_bytes_(BufferLength)
         PUCHAR                   Buffer,
    _In_ ULONG                    BufferLength
    )
{

   PMS_FILTER              pFilter;
   PLIST_ENTRY             Link;
   BOOLEAN                  bFalse = FALSE;
   
   FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
               
   Link = FilterModuleList.Flink;
               
   while (Link != &FilterModuleList)
   {
       pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

       if (BufferLength >= pFilter->FilterModuleName.Length)
       {
           if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
           {
               FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
               return pFilter;
           }
       }
           
       Link = Link->Flink;
   }
   
   FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
   return NULL;
}




