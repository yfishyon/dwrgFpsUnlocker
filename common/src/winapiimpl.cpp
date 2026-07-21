//
// Created by Tofu on 25-6-24.
//
#include "winapiutil.h"
#include <vector>
#include <cstring>

uintptr_t getProcAddressExBuffered(HANDLE hProcess, uintptr_t moduleBase, const char* symbolName) {
    //获取DOS头
    SIZE_T bytesRead;
    IMAGE_DOS_HEADER dosHeader = {};
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dosHeader, sizeof(dosHeader), &bytesRead))
        return 0;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    //解析NT位置并获取
    IMAGE_NT_HEADERS ntHeaders = {};
    uintptr_t ntHeaderAddr = moduleBase + dosHeader.e_lfanew;
    if (!ReadProcessMemory(hProcess, (LPCVOID)ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead))
        return 0;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    //获取导出表
    auto& expData = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expData.VirtualAddress == 0 || expData.Size == 0)
        return 0;

    std::vector<uint8_t> buffer(expData.Size);
    uintptr_t exportBase = moduleBase + expData.VirtualAddress;
    if (!ReadProcessMemory(hProcess, (LPCVOID)exportBase, buffer.data(), buffer.size(), &bytesRead))
        return 0;

    auto* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(buffer.data());
    DWORD* nameRVAs = reinterpret_cast<DWORD*>(buffer.data() + (exportDir->AddressOfNames - expData.VirtualAddress));
    WORD* ordinals = reinterpret_cast<WORD*>(buffer.data() + (exportDir->AddressOfNameOrdinals - expData.VirtualAddress));
    DWORD* functions = reinterpret_cast<DWORD*>(buffer.data() + (exportDir->AddressOfFunctions - expData.VirtualAddress));

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(buffer.data() + (nameRVAs[i] - expData.VirtualAddress));
        if (strcmp(name, symbolName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            return moduleBase + funcRVA;
        }
    }

    return 0;
}

std::wstring PrintProcessGroups() {
    std::wstring ret;

    HANDLE tokenHandle;
    DWORD tokenInfoLength = 0;
    PTOKEN_GROUPS tokenGroups;

    // 打开当前进程的访问令牌
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        return L"无法打开进程访问令牌，错误代码：" + std::to_wstring(GetLastError());
    }

    // 获取组信息的大小
    GetTokenInformation(tokenHandle, TokenGroups, nullptr, 0, &tokenInfoLength);
    tokenGroups = (PTOKEN_GROUPS)malloc(tokenInfoLength);

    // 获取完整的组信息
    if (GetTokenInformation(tokenHandle, TokenGroups, tokenGroups, tokenInfoLength, &tokenInfoLength)) {
        for (DWORD i = 0; i < tokenGroups->GroupCount; i++) {
            SID_NAME_USE sidType;
            TCHAR name[256];
            TCHAR domain[256];
            DWORD nameLen = sizeof(name) / sizeof(TCHAR);
            DWORD domainLen = sizeof(domain) / sizeof(TCHAR);

            // 将 SID 转换为组名
            if (LookupAccountSid(nullptr, tokenGroups->Groups[i].Sid, name, &nameLen, domain, &domainLen, &sidType)) {
                std::wstring groupType = (tokenGroups->Groups[i].Attributes & SE_GROUP_ENABLED) ? L"(启用)" : L"(禁用)";
                ret = std::wstring(L"组名称：") + domain + L"\\" + name + groupType;
            } else {
                ret = L"无法解析 SID 为组名，SID：" + std::to_wstring(uintptr_t (tokenGroups->Groups[i].Sid));
            }
        }
    } else {
        ret = L"获取组信息失败，错误代码：" + std::to_wstring(GetLastError());
    }

    // 清理
    free(tokenGroups);
    CloseHandle(tokenHandle);

    return ret;
}

/* 远程内存锚点扫描 */
uintptr_t ScanRemoteAnchor(HANDLE hProcess, uintptr_t moduleBase, size_t range,
                           const unsigned char* pattern, size_t patternLen)
{
    static const size_t CHUNK = 4096;
    unsigned char buf[CHUNK];
    uintptr_t p = moduleBase;
    uintptr_t end = moduleBase + range;

    while (p + patternLen <= end) {
        size_t want = CHUNK;
        if (p + want > end) want = (size_t)(end - p);
        if (want < patternLen) break;

        SIZE_T got = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)p, buf, want, &got) || got == 0) {
            p = (p + 0x1000) & ~(uintptr_t)0xFFF;
            continue;
        }

        for (size_t i = 0; i + patternLen <= got; ++i) {
            if (memcmp(buf + i, pattern, patternLen) == 0) {
                return p + i;
            }
        }

        uintptr_t next = p + got;
        if (next + patternLen > end) break;
        p = next - (patternLen - 1);
    }
    return 0;
}

/* 远程读取 PE 头中的 SizeOfImage */
size_t GetRemoteModuleSize(HANDLE hProcess, uintptr_t moduleBase)
{
    SIZE_T got = 0;
    IMAGE_DOS_HEADER dos = {0};
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dos, sizeof(dos), &got) || got != sizeof(dos))
        return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS nt = {0};
    uintptr_t ntAddr = moduleBase + dos.e_lfanew;
    if (!ReadProcessMemory(hProcess, (LPCVOID)ntAddr, &nt, sizeof(nt), &got) || got != sizeof(nt))
        return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    return nt.OptionalHeader.SizeOfImage;
}

