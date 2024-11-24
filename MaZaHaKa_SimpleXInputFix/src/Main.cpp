#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "Windows.h"
#include "XMemory.h"

#define PATCHES_CNT 4
#define PATCH_SIZE 6

SIZE_T BytesWrittenHookedFunc[PATCHES_CNT] = { 0 }; // +w flag
char OriginalBytesHookedFunc[PATCHES_CNT][PATCH_SIZE] = {0};

inline static void* InstallHook(void* pAddr, void* pHookedFunc, SIZE_T& BytesWrittenHookedFunc, char* OriginalBytesHookedFunc)
{
	if (!pAddr) { return NULL; }
	// read orig bytes
	SIZE_T bytesRead = 0;
	ReadProcessMemory(GetCurrentProcess(), pAddr, OriginalBytesHookedFunc, PATCH_SIZE, &bytesRead);
	// prepare patch
	char patch[6] = { 0 };
	memcpy_s(patch, 1, "\x68", 1); // [push pHookFunc] Insert 'push' instruction to store the function address on the stack
	memcpy_s(patch + 1, 4, &pHookedFunc, 4); // Write the address of the target function to be called
	memcpy_s(patch + 5, 1, "\xC3", 1); // [ret] End the patch with 'ret' to transfer control to the function address on the stack (instead of 'call')
	// set patch
	//WriteProcessMemory(GetCurrentProcess(), pAddr, patch, sizeof(patch), &BytesWrittenHookedFunc);
	WriteProcessMemory(GetCurrentProcess(), pAddr, patch, PATCH_SIZE, &BytesWrittenHookedFunc);
	return pAddr;
}
inline static void DisableHook(void* pAddr, SIZE_T& BytesWrittenHookedFunc, char* OriginalBytesHookedFunc)
{
	//WriteProcessMemory(GetCurrentProcess(), pAddr, OriginalBytesHookedFunc, sizeof(OriginalBytesHookedFunc), &BytesWrittenHookedFunc); // unpatch
	WriteProcessMemory(GetCurrentProcess(), pAddr, OriginalBytesHookedFunc, PATCH_SIZE, &BytesWrittenHookedFunc); // unpatch
	BytesWrittenHookedFunc = 0;
}
//--------------------------------------------------------


//========= game stuff (Max Payne 1)
// BUG: XInput/DInput buffer 0x8AC2E4 X_Input::s_pKeyboard  sometimes misses hold keys (TMP FIX)
auto X_InputDeviceKeyboard_isPressed = (bool(__thiscall*)(void*, int))0x5184C0;
auto X_InputDeviceKeyboard_isDoubleClicked = (bool(__thiscall*)(void*, int))0x5184D0;
auto X_InputDeviceKeyboard_isSingleClicked = (bool(__thiscall*)(void*, int))0x5184F0;
auto X_InputDeviceKeyboard_isReleased = (bool(__thiscall*)(void*, int))0x518510;

uint8_t DIKToVK[256] = {
	0,         VK_ESCAPE, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', VK_OEM_MINUS, VK_OEM_PLUS, VK_BACK, VK_TAB,
	'Q',       'W',       'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', VK_OEM_4, VK_OEM_6, VK_RETURN, VK_LCONTROL, 'A', 'S',
	'D',       'F',       'G', 'H', 'J', 'K', 'L', VK_OEM_1, VK_OEM_7, VK_OEM_3, VK_LSHIFT, VK_OEM_5, 'Z', 'X', 'C', 'V',
	'B',       'N',       'M', VK_OEM_COMMA, VK_OEM_PERIOD, VK_OEM_2, VK_RSHIFT, VK_MULTIPLY, VK_LMENU, VK_SPACE, VK_CAPITAL,
	VK_F1,     VK_F2,     VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9, VK_F10, VK_NUMLOCK, VK_SCROLL, VK_NUMPAD7, VK_NUMPAD8, VK_NUMPAD9, VK_SUBTRACT,
	VK_NUMPAD4, VK_NUMPAD5, VK_NUMPAD6, VK_ADD, VK_NUMPAD1, VK_NUMPAD2, VK_NUMPAD3, VK_NUMPAD0, VK_DECIMAL, 0, 0, 0, VK_F11, VK_F12,
};

bool GetKeyPress(int dikKey) // GetKeyState
{
	uint8_t vkKey = DIKToVK[dikKey];
	return (GetAsyncKeyState(vkKey) & 0x8000) != 0;
}
//----------------------------------------------------------


bool __fastcall HK_X_InputDeviceKeyboard_isPressed(void* ecx, void* edx, int key)
{
	//DisableHook(X_InputDeviceKeyboard_isPressed, BytesWrittenHookedFunc[0], OriginalBytesHookedFunc[0]);
	//bool res = X_InputDeviceKeyboard_isPressed(ecx, key);
	//InstallHook(X_InputDeviceKeyboard_isPressed, HK_X_InputDeviceKeyboard_isPressed, BytesWrittenHookedFunc[0], OriginalBytesHookedFunc[0]);
	//return res;
	return GetKeyPress(key);
}
bool __fastcall HK_X_InputDeviceKeyboard_isDoubleClicked(void* ecx, void* edx, int key)
{
	DisableHook(X_InputDeviceKeyboard_isDoubleClicked, BytesWrittenHookedFunc[1], OriginalBytesHookedFunc[1]);
	bool res = X_InputDeviceKeyboard_isDoubleClicked(ecx, key);
	InstallHook(X_InputDeviceKeyboard_isDoubleClicked, HK_X_InputDeviceKeyboard_isDoubleClicked, BytesWrittenHookedFunc[1], OriginalBytesHookedFunc[1]);
	return res;
	//return GetKeyPress(key); // todo (no use here)
}
bool __fastcall HK_X_InputDeviceKeyboard_isSingleClicked(void* ecx, void* edx, int key)
{ // if return true or holded GetKeyPress it was activate bunnyhop
	DisableHook(X_InputDeviceKeyboard_isSingleClicked, BytesWrittenHookedFunc[2], OriginalBytesHookedFunc[2]);
	bool res = X_InputDeviceKeyboard_isSingleClicked(ecx, key);
	InstallHook(X_InputDeviceKeyboard_isSingleClicked, HK_X_InputDeviceKeyboard_isSingleClicked, BytesWrittenHookedFunc[2], OriginalBytesHookedFunc[2]);
	return res;
	//return GetKeyPress(key); // todo (temp)
}
bool __fastcall HK_X_InputDeviceKeyboard_isReleased(void* ecx, void* edx, int key)
{
	//DisableHook(X_InputDeviceKeyboard_isReleased, BytesWrittenHookedFunc[3], OriginalBytesHookedFunc[3]);
	//bool res = X_InputDeviceKeyboard_isReleased(ecx, key);
	//InstallHook(X_InputDeviceKeyboard_isReleased, HK_X_InputDeviceKeyboard_isReleased, BytesWrittenHookedFunc[3], OriginalBytesHookedFunc[3]);
	//return res;
	return !GetKeyPress(key);
}

void InitPatch()
{
    //{ AllocConsole(); freopen("CONOUT$", "w", stdout); } // dbg
	InstallHook(X_InputDeviceKeyboard_isPressed, HK_X_InputDeviceKeyboard_isPressed, BytesWrittenHookedFunc[0], OriginalBytesHookedFunc[0]);
	//InstallHook(X_InputDeviceKeyboard_isDoubleClicked, HK_X_InputDeviceKeyboard_isDoubleClicked, BytesWrittenHookedFunc[1], OriginalBytesHookedFunc[1]);
	InstallHook(X_InputDeviceKeyboard_isSingleClicked, HK_X_InputDeviceKeyboard_isSingleClicked, BytesWrittenHookedFunc[2], OriginalBytesHookedFunc[2]);
	InstallHook(X_InputDeviceKeyboard_isReleased, HK_X_InputDeviceKeyboard_isReleased, BytesWrittenHookedFunc[3], OriginalBytesHookedFunc[3]);
}


//========== entries
int main() { InitPatch(); return 0; }

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        //CreateThread(NULL, 0, SpooferEntry, NULL, 0, NULL);
        main();
    }

    return TRUE;
}