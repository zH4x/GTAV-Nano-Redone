//Hooking.cpp
#pragma once
#include "stdafx.h"

ScriptThread*(*GetActiveThread)() = nullptr;
HMODULE _hmoduleDLL;
HANDLE mainFiber;
DWORD wakeAt;

uint64_t* Hooking::m_frameCount;
bool(*Hooking::is_DLC_present)() = nullptr;
static uint64_t m_worldPtr;
static BlipList* m_blipList;
static std::vector<LPVOID> m_hookedNative;
static uint64_t** m_globalPtr;
static std::vector<void*> EventPtr;
static const int EVENT_COUNT = 78;
static char EventRestore[EVENT_COUNT] = {};
static void* m_nativeTable;
static char object_spawn[24];
static char model_bypass[2];
static void* m_object_spawn;
static void* m_model_bypass;
static EntityPool** m_entity_pool;
static uint64_t m_player_list;
const char NOP = '\x90';

/* Start Hooking */
void Hooking::Start(HMODULE hmoduleDLL)
{
	_hmoduleDLL = hmoduleDLL;
	Log::Init(hmoduleDLL);
	FindPatterns();
	if (!InitializeHooks()) 
		Cleanup();
}

BOOL Hooking::InitializeHooks()
{
	BOOL returnVal = TRUE;

	if (!iHook.Initialize()) {

		Log::Error("Failed to initialize InputHook");
		returnVal = FALSE;
	}

	if (MH_Initialize() != MH_OK) {
		Log::Error("MinHook failed to initialize");
		returnVal = FALSE;
	}

	if (!HookNatives()) {

		Log::Error("Failed to initialize NativeHooks");
		returnVal = FALSE;
	}

	return returnVal;
}

Hooking::NativeHandler(*provideNative)(void* nativeTable, uint64_t nativeHash) = nullptr;
Hooking::NativeHandler Hooking::GetNativeHandler(uint64_t origHash)
{
	return provideNative(m_nativeTable, CrossMapping::MapNative(origHash));
}

bool (*OG_IS_DLC_PRESENT)(uint32_t) = nullptr;
bool HK_IS_DLC_PRESENT(uint32_t hash)
{
	static uint64_t	last = 0;
	uint64_t cur = *Hooking::m_frameCount;
	if (last != cur)
	{
		last = cur;
		Hooking::onTickInit();
	}
	if (hash == 0x96F02EE6)
		return true;
	return OG_IS_DLC_PRESENT(hash);
}

bool Hooking::HookNatives()
{
	MH_STATUS status = MH_CreateHook(Hooking::is_DLC_present, HK_IS_DLC_PRESENT, reinterpret_cast<void**>(&OG_IS_DLC_PRESENT));
	return (status == MH_OK || status == MH_ERROR_ALREADY_CREATED) && MH_EnableHook(Hooking::is_DLC_present) == MH_OK;

}

void __stdcall ScriptFunction(LPVOID lpParameter)
{
	try
	{
		ScriptMain();
	}
	catch (...)
	{
		Log::Fatal("Failed scriptFiber");
	}
}

void Hooking::onTickInit()
{
	if (mainFiber == nullptr)
		mainFiber = ConvertThreadToFiber(nullptr);
	if (mainFiber == nullptr)
		mainFiber = GetCurrentFiber();
	if (timeGetTime() < wakeAt)
		return;
	static HANDLE scriptFiber;
	if (scriptFiber)
		SwitchToFiber(scriptFiber);
	else
		scriptFiber = CreateFiber(NULL, ScriptFunction, nullptr);
}

void Error(char* msg)
{
	Log::Error(msg);
	Hooking::Cleanup();
}

void iterateBlips()
{
	uint64_t base = reinterpret_cast<uint64_t>(GetModuleHandleA(nullptr));
	BlipList* p = reinterpret_cast<BlipList*>(base + 0x20097A0);
	for (size_t i = 0; i < 1500; i++)
	{
		if (!p->m_Blips[i])
		{
			Log::Msg("Help %d\n", i);
			continue;
		}
		Log::Msg("%d x:%.2f y: %.2f\n", i, p->m_Blips[i]->coords.x, p->m_Blips[i]->coords.y);
	}

}

void Hooking::FindPatterns()
{
	HANDLE steam = GetModuleHandleA("steam_api64.dll");

	char* ptr;
	if (nullptr == (Hooking::is_DLC_present = ptrScan<bool(*)()>("48 89 5C 24 ? 57 48 83 EC 20 81 F9")))
		Error("Error in finding IS_DLC_PRESENT");

	Log::Msg("Get Frame Count...");
	if (nullptr == (ptr = ptrScan("8B 15 ? ? ? ? 41 FF CF")))
		Error("Error in finding frame_count");
	Hooking::m_frameCount = rel<uint64_t*>(ptr, 2);

	Log::Msg("Getting vector3 result fixer func...");
	if (nullptr == (scrNativeCallContext::SetVectorResults = ptrScan<void(*)(scrNativeCallContext*)>("83 79 18 00 48 8B D1 74 4A FF 4A 18")))
		Error("Error in finding SetVectorResults");

	Log::Msg("Getting World Pointer...");
	if (nullptr == (ptr = ptrScan("48 8B 05 ? ? ? ? 45 ? ? ? ? 48 8B 48 08 48 85 C9 74 07")))
		Error("Error in finding the World Pointer");
	m_worldPtr = rel<uint64_t>(ptr);

	Log::Msg("Getting Blip List...");
	if (nullptr == (ptr = ptrScan("4C 8D 05 ? ? ? ? 0F B7 C1")))
		Error("Error in finding the Bliplist");
	m_blipList = rel<BlipList*>(ptr);
		
	Log::Msg("Getting active script thread...");
	if (nullptr == (ptr = ptrScan("E8 ? ? ? ? 48 8B 88 10 01 00 00")))
		Error("Error in finding the Active Script Thread");
	GetActiveThread = rel<ScriptThread*(*)()>(ptr, 1);

	Log::Msg("Getting Entity Pool List Pointer...");
	if (nullptr == (ptr = ptrScan("4C 8B 0D ? ? ? ? 44 8B C1 49 8B 41 08")))
		Error("Error in finding the Entity Pool Function");
	m_entity_pool = rel<EntityPool**>(ptr);

	Log::Msg("Getting Player List Pointer...");
	if (nullptr == (ptr = ptrScan("48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B CF")))
		Error("Error in finding the Player List Function");
	m_player_list = *rel<uint64_t*>(ptr);

	Log::Msg("Getting Global Pointer...");
	if (nullptr == (ptr = ptrScan("4C 8D 05 ? ? ? ? 4D 8B 08 4D 85 C9 74 11")))
		Error("Error in finding the Global Pointer");
	m_globalPtr = rel<uint64_t**>(ptr);

	Log::Msg("Getting Event Hooks...");
	if (nullptr == (ptr = ptrScan("48 83 EC 28 E8 ? ? ? ? 48 8B 0D ? ? ? ? 4C 8D 0D ? ? ? ? 4C 8D 05 ? ? ? ? BA 03")))
		Error("Error in getting the Event Hooks");
	for (int i = 0; i != EVENT_COUNT; ptr++, i++)
		EventPtr.push_back(rel(ptrScan("4C 8D 05", reinterpret_cast<uintptr_t>(ptr))));

	Log::Msg("Initializing natives...");
	if (nullptr == (ptr = ptrScan("48 8D 0D ? ? ? ? 48 8B 14 FA")))
		Error("Error in Finding the Native Map");
	m_nativeTable = rel(ptr);
	provideNative = *rel<Hooking::NativeHandler(*)(void*, uint64_t)>(ptr, 12);
	CrossMapping::initNativeMap();
	
	Log::Msg("Bypassing Object restrictions..");
	if (nullptr != (m_object_spawn = ptrScan("48 85 C0 0F 84 ? ? ? ? 8B 48 50")))
	{
		memcpy_s(object_spawn, sizeof(object_spawn), m_object_spawn, sizeof(object_spawn));
		// memset(m_object_spawn, NOP, sizeof(object_spawn));
	}
	else
	{
		Log::Msg("Error in finding the Object Spawn Bypass");
	}

	if (nullptr != (ptr = ptrScan("48 8B C8 FF 52 30 84 C0 74 05 48")))
	{
		m_model_bypass = ptr + 8;
		memcpy_s(model_bypass, sizeof(model_bypass), m_model_bypass, sizeof(model_bypass));
		// memset(m_model_bypass, NOP, sizeof(model_bypass));
	}
	else
	{
		Log::Msg("Error in finding the Model Bypass");
	}

	 
	
	auto& symbolTable = CrossMapping::getMap();
	for (auto& it = symbolTable.begin(); it != symbolTable.end(); it++)
		Log::Msg("%#llx,%#llx,%#llx", it->first, it->second, (char*)provideNative(m_nativeTable, it->second) - (char*)GetModuleHandleA(nullptr));
	
	
	Log::Msg("GTA V ready!");
}

__int64 __fastcall sub_7FF6F61E3358(int a1)
{
	__int64 v1; // r8
	__int64 v2; // rax
	__int64 result; // rax

	if (a1 != -1
		&& ((v1 = (unsigned int)(a1 >> 8), *(BYTE *)(v1 + *(uint64_t*)(m_entity_pool + 8)) != (BYTE)a1) ? (v2 = 0i64) : (v2 = *(uint64_t*)m_entity_pool + (unsigned int)(v1 * *(DWORD*)(m_entity_pool + 0x14))),
			v2))
	{
		result = *(uint64_t*)(v2 + 8);
	}
	else
	{
		result = 0i64;
	}
	return result;
}


uint64_t Hooking::getWorldPtr()
{
	return m_worldPtr;
}

void WAIT(DWORD ms)
{
	wakeAt = timeGetTime() + ms;
	SwitchToFiber(mainFiber);
}

void Hooking::Cleanup()
{
	Log::Msg("Cleaning up hooks");

	if (m_object_spawn != nullptr)
		memcpy_s(m_object_spawn, sizeof(object_spawn), object_spawn, sizeof(object_spawn));

	if (m_model_bypass != nullptr)
		memcpy_s(m_model_bypass, sizeof(m_model_bypass), model_bypass, sizeof(m_model_bypass));

	iHook.keyboardHandlerUnregister(OnKeyboardMessage);
	iHook.Remove();
	bool b = (MH_DisableHook(&ResetWriteWatch) != MH_OK && MH_RemoveHook(&ResetWriteWatch) != MH_OK);
	b = (MH_DisableHook(Hooking::is_DLC_present) != MH_OK && MH_RemoveHook(Hooking::is_DLC_present) != MH_OK);
	
	for (int i = 0; i < m_hookedNative.size(); i++)
		b = (MH_DisableHook(m_hookedNative[i]) != MH_OK && MH_RemoveHook(m_hookedNative[i]) != MH_OK);
	MH_Uninitialize();
	FreeLibraryAndExitThread(static_cast<HMODULE>(_hmoduleDLL), 1);
}

void Hooking::defuseEvent(RockstarEvent e, bool toggle)
{
	static const unsigned char retn = 0xC3;
	char* p = reinterpret_cast<char*>(EventPtr[e]);
	if (toggle)
	{
		if (EventRestore[e] == 0)
			EventRestore[e] = p[0];
		*p = retn;
	}
	else
	{
		if (EventRestore[e] != 0)
			*p = EventRestore[e];
	}
}

uint64_t** Hooking::getGlobalPtr()
{
	return m_globalPtr;
}