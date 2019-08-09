# MiniFilter
a simple example for minifilter


实现目的：监视文件创建，文件删除，文件重命名。屏蔽某名称文件的创建。

框架：MiniFilter。

驱动层逻辑：初始化框架。
定义过滤操作（IRP_MJ_CREATE和IRP_MJ_SET_INFORMATION）。
初始化框架，开始过滤。
定义通信端口。
初始化通信端口。
开始通信。
用户层逻辑：打开通信端口。
			主线程循环输入需要过滤的文件名。
			开新线程接收驱动发回来的文件信息。

坑点：
1.	下载的7600框架样本NTDDI_VERSION NTDDI_WINXPSP2需要定义这个才能兼容XP系统。
2.	CallBack过滤里面要以IRP_MJ_OPERATION_END结尾。
3.	过滤分为Pre操作和Post操作，在Pre操作里面有一个FLT_PREOP_SUCCESS_WITH_CALLBACK和FLT_PREOPSUCCESS_NO_CALLBACK代表有没有后置操作。
4.	IRP_MJ_CREATE里面可能会创建文件夹而不是文件。经实验发现，PFLT_CALLBACK_DATA里面的Iopb->Paraments.Create.Options的四个字节，第一个字节表示CreateFile的DispositionValues，后面三个字节表示OptionFlags。OptionFlags里面有一个选项是CreateDirectory，如果存在就是文件夹。
5.	IRP_MJ_CREATE里面有可能是打开文件而不是创建文件，这里处理了一下是打开文件还是创建文件。如果是FILE_OPEN选项直接过滤掉，不属于想操作的类型。如果是FILE_OPEN_IF或者FILE_OVERWRITE_IF则去调用CreateFile（FILE_OPEN）判定文件是否存在。如果存在说明是打开操作，否则是创建操作。
6.	FltGetDestinationFileNameInformation 重命名操作则是有一点不一样，是调用这个函数获取想要改的名字。
7.	MiniFilter有一点很有趣，就是是一个NT驱动，但是可以不存在unload函数，只需要写一个unload函数挂到过滤器上即可，而不需要给Driver写一个卸载函数。
8.	需要导入fltMgr.lib这个lib。
