//
// Created by Tofu on 25-6-24.
//

#ifndef DWRGFPSUNLOCKER_WINAPIUTIL_H
#define DWRGFPSUNLOCKER_WINAPIUTIL_H

#include <windows.h>
#include <TlHelp32.h>

#include <string>
#include <iostream>


inline
std::pair<HWND, DWORD> getFocusedWindowInfo() {
    HWND hwnd = GetForegroundWindow();   // 获取当前活动窗口句柄
    if (!hwnd)
        return {NULL, 0};

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid); // 获取窗口所属进程ID
    return {hwnd, pid};
}

/**
 * @return 若没有符合的窗口，返回NULL
 */
inline
HWND queryTopCognWindow(LPCWSTR title)
{
    HWND hwnd = GetTopWindow(NULL);
    while (hwnd != NULL) {
        wchar_t thattitle[256];
        GetWindowTextW(hwnd , thattitle, 256);
        if (wcscmp(title, thattitle) == 0) {
            return hwnd;
        }
        hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
    }
    return NULL;
}

inline std::wstring U8_2_U16(const std::string_view& u8str) {
    int len = MultiByteToWideChar(CP_UTF8, 0,
        u8str.data(), u8str.size(),
        nullptr, 0
    );

    if (len == 0) return {};

    std::wstring ret(len, 0);
    MultiByteToWideChar(CP_UTF8, 0,
        u8str.data(),u8str.size(),
        ret.data(),len
    );
    return ret;
}

inline std::wstring U8_2_U16(const char* c_u8str)
{
    if (!c_u8str)return {};
    return U8_2_U16(std::string_view(c_u8str));
}

inline std::wstring U8_2_U16(const std::string& u8str)
{
    return U8_2_U16(std::string_view(u8str));
}



inline
uintptr_t GetModuleBaseAddress(DWORD processId, const char* moduleName) {
    uintptr_t moduleBaseAddress = 0;
    std::wstring wmoduleName = U8_2_U16(moduleName);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32W);/** 2025.6.19 bugfix log：原来用MODULEENTRY32W填入的size得是MODULEENTRY32W 不兑，这不是理所当然的吗？*/

        if (Module32FirstW(hSnapshot, &moduleEntry)) {
            do {
//#ifdef _DEBUG
//                std::cerr<<moduleEntry.szModule<<'\t';
//#endif
                if (
                        wmoduleName == moduleEntry.szModule
                        ) {
                    moduleBaseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnapshot, &moduleEntry));
        }
        else{
            DWORD error = GetLastError();
            std::cerr << "Module32FirstW failed with error: " << error << std::endl;
        }
        CloseHandle(hSnapshot);
    }
    return moduleBaseAddress;
}

uintptr_t getProcAddressExBuffered(HANDLE hProcess, uintptr_t moduleBase, const char* symbolName);

/* 远程内存锚点扫描: 在 [moduleBase, moduleBase+range) 内找第一个匹配 pattern 的字节串 */
uintptr_t ScanRemoteAnchor(HANDLE hProcess, uintptr_t moduleBase, size_t range,
                           const unsigned char* pattern, size_t patternLen);

/* 远程读 PE 头 SizeOfImage, 返回模块映射大小 */
size_t GetRemoteModuleSize(HANDLE hProcess, uintptr_t moduleBase);

std::wstring PrintProcessGroups();

#endif //DWRGFPSUNLOCKER_WINAPIUTIL_H
