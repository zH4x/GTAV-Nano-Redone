#pragma once

class Hooking
{
private:
	static BOOL InitializeHooks();
	static void FindPatterns();

public:
	static uint64_t* m_frameCount;
	static bool(*is_DLC_present)();

	static void Start(HMODULE hmoduleDLL);
	static void Cleanup();
	static uint64_t getWorldPtr();
	static void onTickInit();
	static bool HookNatives();
	static uint64_t** getGlobalPtr();
	uint64_t* Hooking::getGlobalPtr(int index);
	static void defuseEvent(RockstarEvent e, bool toggle);

	// Native function handler type
	typedef void(__cdecl* NativeHandler)(scrNativeCallContext* context);
	static NativeHandler GetNativeHandler(uint64_t origHash);
};

void WAIT(DWORD ms);


enum eThreadState
{
	ThreadStateIdle = 0x0,
	ThreadStateRunning = 0x1,
	ThreadStateKilled = 0x2,
	ThreadState3 = 0x3,
	ThreadState4 = 0x4,
};

struct scrThreadContext
{
	int ThreadID;
	int ScriptHash;
	eThreadState State;
	int _IP;
	int FrameSP;
	int _SPP;
	float TimerA;
	float TimerB;
	int TimerC;
	int _mUnk1;
	int _mUnk2;
	int _f2C;
	int _f30;
	int _f34;
	int _f38;
	int _f3C;
	int _f40;
	int _f44;
	int _f48;
	int _f4C;
	int _f50;
	int pad1;
	int pad2;
	int pad3;
	int _set1;
	int pad[17];
};

struct scrThread
{
	void *vTable;
	scrThreadContext m_ctx;
	void *m_pStack;
	void *pad;
	void *pad2;
	const char *m_pszExitMessage;
};

struct ScriptThread : scrThread
{
	const char Name[64];
	void *m_pScriptHandler;
	const char gta_pad2[40];
	const char flag1;
	const char m_networkFlag;
	bool bool1;
	bool bool2;
	bool bool3;
	bool bool4;
	bool bool5;
	bool bool6;
	bool bool7;
	bool bool8;
	bool bool9;
	bool bool10;
	bool bool11;
	bool bool12;
	const char gta_pad3[10];
};
