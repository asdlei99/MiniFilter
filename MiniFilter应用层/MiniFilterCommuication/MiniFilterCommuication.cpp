#include <iostream>
#include <Windows.h>
#include <fltUser.h>

#pragma comment(lib,"fltLib.lib")
#pragma comment(lib,"fltMgr.lib")

using namespace std;

typedef struct _ZTYMESSAGE
{
	ULONG Flag;													//表示是创建还是删除还是重命名，创建0，删除1，重命名2
	WCHAR PATH[300];
}ZTYMESSAGE, *PZTYMESSAGE;

HANDLE m_ClintPort;

BOOL  Flag = TRUE;

DWORD WINAPI ThreadProc(PVOID)
{
	WCHAR Message[1];

	HRESULT status;

	ZTYMESSAGE m_Message;

	DWORD ReturnLength;

	while (Flag)
	{
		status = FilterSendMessage(m_ClintPort, Message, 1, &m_Message, sizeof(m_Message), &ReturnLength);

		if (status == S_OK)
		{
			switch (m_Message.Flag)
			{
			case 0:
				cout << "创建，路径为：";
				break;
			case 1:
				cout << "删除，路径为：";
				break;
			case 2:
				cout << "重命名，路径为：";
				break;
			default:
				break;
			}

			wcout << m_Message.PATH << endl;
		}
	}

	return 0;
}

int main()
{
	DWORD ReturnLength;

	HRESULT status = FilterConnectCommunicationPort(L"\\ztyPort",
		0,
		NULL,
		0,
		NULL,
		&m_ClintPort);

	setlocale(0, "chs");

	if (status != S_OK)
	{
		cout << "连接失败！" << endl;
		system("pause");
		return 0;
	}

	CloseHandle(CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL));

	WCHAR Message[100];											

	cout << "输入END结束进程！" << endl;

	while (true)
	{
		wcin >> Message;

		if (!lstrcmpW(Message, L"END"))
		{
			Flag = FALSE;

			Sleep(50);

			return 0;
		}


		status = FilterSendMessage(m_ClintPort, Message, 2 * (lstrlenW(Message) + 1), NULL, 0, &ReturnLength);

		if (status != S_OK)
			cout << "发送失败,请重新发送！" << endl;

	}

	system("pause");

	return 0;
}