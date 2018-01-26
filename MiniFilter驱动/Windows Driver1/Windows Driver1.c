#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddscsi.h>		

FLT_PREOP_CALLBACK_STATUS
NPPreCreate(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
NPPreSetInformation(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

NTSTATUS Unload(__in FLT_FILTER_UNLOAD_FLAGS Flags);

PFLT_FILTER m_Filter;

PFLT_PORT m_ServerPort;

PFLT_PORT m_ClientPort;

LIST_ENTRY m_ListHead;											//用来保存要过滤的文件名的链表

KSPIN_LOCK m_SpinLock;											//用来配合的锁

LIST_ENTRY x_ListHead;											//用来保存返回文件信息的链表

KSPIN_LOCK x_SpinLock;											//用来配合的的锁

typedef struct _FileName
{
	LIST_ENTRY ListEntry;
	WCHAR Name[40];												//测试用，文件名假定不超过19个字符
}FILENAME,*PFILENAME;

typedef struct _ZTYMESSAGE
{
	ULONG Flag;													//表示是创建还是删除还是重命名，创建0，删除1，重命名2
	WCHAR PATH[300];											
}ZTYMESSAGE, *PZTYMESSAGE;

typedef struct _FILEPATH
{
	LIST_ENTRY ListEntry;
	ZTYMESSAGE Message;
}FILEPATH,*PFILEPATH;

CONST FLT_OPERATION_REGISTRATION CallBack[] = {
	{
		IRP_MJ_CREATE,
		0,
		NPPreCreate,
		NULL
	},
	{
		IRP_MJ_SET_INFORMATION,							//重命名和删除都是在SET_INFORMATION中
		0,
		NPPreSetInformation,
		NULL
	},
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	NULL,
	NULL,
	CallBack,
	Unload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

BOOLEAN JudgeLengthOfMessage()
{
	KIRQL irql;

	ULONG i = 0;

	PLIST_ENTRY TempList;

	KeAcquireSpinLock(&x_SpinLock, &irql);

	TempList = x_ListHead.Blink;

	while (TempList != &x_ListHead)
	{
		++i;

		TempList = TempList->Blink;
	}

	KeReleaseSpinLock(&x_SpinLock, irql);

	if (i < 1000)
		return TRUE;

	KdPrint(("超过50条消息不可以再添加了！\n"));

	return FALSE;
}

NTSTATUS JudgeFileExist(PUNICODE_STRING FileName)						//判断文件是否存在
{
	NTSTATUS status;

	HANDLE FileHandle;														//如果遇到Open_IF就先去判断是否存在，如果不存在就记下这个目录。

	IO_STATUS_BLOCK IoBlock;

	OBJECT_ATTRIBUTES ObjectAttributes;

	InitializeObjectAttributes(&ObjectAttributes, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&FileHandle, GENERIC_ALL, &ObjectAttributes, &IoBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (NT_SUCCESS(status))
		ZwClose(FileHandle);

	return status;
}

BOOLEAN JudgeFile(PUNICODE_STRING FileName)								//判断文件名是否是我们想要过滤的文件名
{
	ULONG i = 0;

	ULONG j;

	KIRQL irql;

	PFILENAME Filter_FileName;

	PLIST_ENTRY TempList;

	TempList = m_ListHead.Blink;

	while (TempList != &m_ListHead)
	{
		Filter_FileName = (PFILENAME)TempList;

		i = 0;

		while (i < (FileName->Length / 2))
		{
			j = 0;

			while (Filter_FileName->Name[j] != L'\0' && (i + j) < FileName->Length / 2)
			{
				if (Filter_FileName->Name[j] != FileName->Buffer[i + j])
					break;
				++j;
			}

			if (Filter_FileName->Name[j] == L'\0')
				return TRUE;

			++i;
		}

		TempList = TempList->Blink;
	}

	return FALSE;
}

FLT_PREOP_CALLBACK_STATUS m_ReNameFile(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	NTSTATUS status;

	PFILE_RENAME_INFORMATION pReNameInfo;

	PFLT_FILE_NAME_INFORMATION NameInfo;

	PFILEPATH FilePath;

	ULONG i = 0;

	pReNameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

	status = FltGetDestinationFileNameInformation(FltObjects->Instance,
		Data->Iopb->TargetFileObject, 
		pReNameInfo->RootDirectory, 
		pReNameInfo->FileName, 
		pReNameInfo->FileNameLength, 
		FLT_FILE_NAME_NORMALIZED,
		&NameInfo);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Get Destination Name Fail!\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (JudgeFile(&NameInfo->Name))																//禁止出现对应名称的文件。							
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		FltReleaseFileNameInformation(NameInfo);
		return FLT_PREOP_COMPLETE;
	}

	if (!JudgeLengthOfMessage())
	{
		FltReleaseFileNameInformation(NameInfo);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FilePath = (PFILEPATH)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILEPATH), 'ytz');

	if (FilePath != NULL)
	{
		FilePath->Message.Flag = 2;
		
		while (i < NameInfo->Name.Length / 2)
		{
			FilePath->Message.PATH[i] = NameInfo->Name.Buffer[i];
			++i;
		}

		FilePath->Message.PATH[NameInfo->Name.Length / 2] = L'\0';

		ExInterlockedInsertTailList(&x_ListHead, (PLIST_ENTRY)FilePath, &x_SpinLock);

		KdPrint(("Rename:%ws\n", FilePath->Message.PATH));
	}

	//KdPrint(("ReName:%wZ\n", &NameInfo->Name));

	FltReleaseFileNameInformation(NameInfo);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS m_DeleteFile(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	NTSTATUS status;

	BOOLEAN isDir;

	PFLT_FILE_NAME_INFORMATION NameInfo;

	PFILEPATH FilePath;

	ULONG i = 0;

	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);

	if (!NT_SUCCESS(status))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (isDir)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;					//这里代表如果是文件夹，就不去管它。

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED
		| FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Query Name Fail!\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FltParseFileNameInformation(NameInfo);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Parse Name Fail!\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!JudgeLengthOfMessage())
	{
		FltReleaseFileNameInformation(NameInfo);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FilePath = (PFILEPATH)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILEPATH), 'ytz');

	if (FilePath != NULL)
	{
		FilePath->Message.Flag = 1;

		while (i < NameInfo->Name.Length / 2)
		{
			FilePath->Message.PATH[i] = NameInfo->Name.Buffer[i];
			++i;
		}

		FilePath->Message.PATH[NameInfo->Name.Length / 2] = L'\0';

		ExInterlockedInsertTailList(&x_ListHead, (PLIST_ENTRY)FilePath, &x_SpinLock);

		KdPrint(("Delete:%ws\n", FilePath->Message.PATH));
	}

	//KdPrint(("Delete:%wZ\n", &NameInfo->Name));

	FltReleaseFileNameInformation(NameInfo);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
NPPreSetInformation(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
{
	if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)						//重命名操作
		return m_ReNameFile(Data,FltObjects);
	else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)				//删除操作
		return m_DeleteFile(Data, FltObjects);
	else
		return FLT_PREOP_SUCCESS_NO_CALLBACK;																			//其他操作不管，直接返回SUCCESS

}

FLT_PREOP_CALLBACK_STATUS
NPPreCreate(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
{
	NTSTATUS status;

	ULONG CreatePosition;

	ULONG Position;

	PFLT_FILE_NAME_INFORMATION NameInfo;

	PFILEPATH FilePath;

	ULONG i = 0;

	Position = Data->Iopb->Parameters.Create.Options;

	CreatePosition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;	//经过反复检验发现，Create.Options的分布是这样子的，第一字节是create disposition values，后面三个字节是option flags

	if (Position & FILE_DIRECTORY_FILE)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;								//如果发现是文件夹选项直接返回

	if (CreatePosition == FILE_OPEN)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;								//如果是FILE_OPEN打开文件，直接返回

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Query Name Fail!\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltParseFileNameInformation(NameInfo);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Parse Name Fail!\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (JudgeFile(&NameInfo->Name))
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		FltReleaseFileNameInformation(NameInfo);
		return FLT_PREOP_COMPLETE;
	}

	if (CreatePosition == FILE_OPEN_IF || CreatePosition == FILE_OVERWRITE_IF)						//如果这里出现了****IF代表如果存在则****，否则创建，所以需要先判断是否存在，如果存在则不在过滤范围，否则就是过滤范围内了。
	{
		//KdPrint(("FILE_OPEN_IF OR FILE_OVERWRITE_IF\n"));
		if (NT_SUCCESS(JudgeFileExist(&NameInfo->Name)))
		{
			//KdPrint(("文件已经存在！\n"));
			FltReleaseFileNameInformation(NameInfo);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}

	if (!JudgeLengthOfMessage())
	{
		FltReleaseFileNameInformation(NameInfo);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FilePath = (PFILEPATH)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILEPATH), 'ytz');

	if (FilePath != NULL)
	{
		FilePath->Message.Flag = 0;

		while (i < NameInfo->Name.Length / 2)
		{
			FilePath->Message.PATH[i] = NameInfo->Name.Buffer[i];
			++i;
		}

		FilePath->Message.PATH[i] = L'\0';

		ExInterlockedInsertTailList(&x_ListHead, (PLIST_ENTRY)FilePath, &x_SpinLock);

		KdPrint(("Create:%ws\n", FilePath->Message.PATH));
	}

	//KdPrint(("Create:%wZ\n", &NameInfo->Name));

	FltReleaseFileNameInformation(NameInfo);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
m_Connect(
__in PFLT_PORT ClientPort,
__in PVOID ServerPortCookie,
__in_bcount(SizeOfContext) PVOID ConnectionContext,
__in ULONG SizeOfContext,
__deref_out_opt PVOID *ConnectionCookie
)
{
	if (ClientPort == NULL)
	{
		KdPrint(("ClinetPort is NULL!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	m_ClientPort = ClientPort;

	return STATUS_SUCCESS;
}

VOID
m_Disconnect(
__in_opt PVOID ConnectionCookie
)
{
	FltCloseClientPort(m_Filter, &m_ClientPort);
}

NTSTATUS
m_Message(
__in_opt PVOID PortCookie,
__in_bcount_opt(InputBufferLength) PVOID InputBuffer,
__in ULONG InputBufferLength,
__out_bcount_part_opt(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
__in ULONG OutputBufferLength,
__out PULONG ReturnOutputBufferLength
)
{
	WCHAR *InputMessage;

	PFILENAME FileName;

	PFILEPATH FilePath;

	ULONG i = 0;

	if (InputBufferLength != 1)
	{
		InputMessage = (WCHAR *)InputBuffer;

		FileName = (PFILENAME)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILENAME), 'ytz');

		if (FileName == NULL)
		{
			KdPrint(("分配内存失败！\n"));
			return STATUS_UNSUCCESSFUL;
		}

		while (i < InputBufferLength / 2)
		{
			FileName->Name[i] = InputMessage[i];
			++i;
		}

		KdPrint(("Length:%d\n", i));

		KdPrint(("%ws\n", FileName->Name));

		ExInterlockedInsertTailList(&m_ListHead, (PLIST_ENTRY)FileName,&m_SpinLock);
	}
	else if (OutputBufferLength != 0)
	{
		FilePath = (PFILEPATH)ExInterlockedRemoveHeadList(&x_ListHead, &x_SpinLock);

		if (FilePath == NULL)
			return STATUS_UNSUCCESSFUL;									//链表没数据

		if (OutputBufferLength != sizeof(ZTYMESSAGE))
			return STATUS_UNSUCCESSFUL;									//应用层缓冲区不足

		RtlCopyMemory(OutputBuffer, &FilePath->Message, sizeof(ZTYMESSAGE));

		ExFreePoolWithTag(FilePath, 'ytz');
	}

	return  STATUS_SUCCESS;
}

NTSTATUS Unload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	PFILENAME m_list;

	PFILEPATH x_list;

	KdPrint(("Unload Success!\n"));

	FltCloseCommunicationPort(m_ServerPort);

	FltUnregisterFilter(m_Filter);

	m_list = (PFILENAME)ExInterlockedRemoveHeadList(&m_ListHead, &m_SpinLock);

	while (m_list != NULL)
	{
		ExFreePoolWithTag(m_list, 'ytz');
		m_list = (PFILENAME)ExInterlockedRemoveHeadList(&m_ListHead, &m_SpinLock);
	}

	x_list = (PFILEPATH)ExInterlockedRemoveHeadList(&x_ListHead, &x_SpinLock);

	while (x_list != NULL)
	{
		ExFreePoolWithTag(x_list, 'ytz');
		x_list = (PFILENAME)ExInterlockedRemoveHeadList(&x_ListHead, &x_SpinLock);
	}

	return STATUS_SUCCESS;
}

NTSTATUS InitFltFilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &m_Filter);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Register Filter UnSuccess!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	status = FltStartFiltering(m_Filter);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Start Filter UnSuccess!\n"));
		FltUnregisterFilter(m_Filter);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS InitcommunicationPort()
{
	PSECURITY_DESCRIPTOR SecurityDes;

	OBJECT_ATTRIBUTES ObjectAttributes;

	UNICODE_STRING PortName;

	NTSTATUS status;

	status = FltBuildDefaultSecurityDescriptor(&SecurityDes, FLT_PORT_ALL_ACCESS);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("BuilDefaultSecurityDescriptor Fail!Erorr Code is :%x \n", status));
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&PortName, L"\\ztyPort");

	InitializeObjectAttributes(&ObjectAttributes,
		&PortName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		SecurityDes
		);

	status = FltCreateCommunicationPort(m_Filter,
		&m_ServerPort,
		&ObjectAttributes,
		NULL,
		m_Connect,																//MiniConnect
		m_Disconnect,															//MiniDisConnect
		m_Message,																//MiniMessage
		1																		//最大连接数量
		);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("CreateCommuicationPort Fail!\n"));
		FltFreeSecurityDescriptor(SecurityDes);
		return STATUS_UNSUCCESSFUL;
	}

	FltFreeSecurityDescriptor(SecurityDes);

	return STATUS_SUCCESS;
}

NTSTATUS Init()
{
	KdPrint(("Entry Driver!\n"));

	InitializeListHead(&m_ListHead);

	KeInitializeSpinLock(&m_SpinLock);

	InitializeListHead(&x_ListHead);

	KeInitializeSpinLock(&x_SpinLock);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	Init();

	if (!NT_SUCCESS(InitFltFilter(DriverObject)))
		return STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(InitcommunicationPort()))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}