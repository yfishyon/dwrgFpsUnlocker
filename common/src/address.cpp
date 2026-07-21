//
// Created by Tofu on 25-6-16.
//

#include "winapiutil.h"
#include "fpssetter.h"
#include "errreport.h"

#ifdef _DEBUG
#include <psapi.h>
#endif

#include <QFile>
#include <QDebug>

#include <filesystem>

bool FpsSetter::getAddress() {

    static constexpr char targetModuleName[]    = "neox_engine.dll";

    /* 锚点: "python" + 10 个 \0 (共 16 字节) */
    static const unsigned char anchor[16] = {
        0x70, 0x79, 0x74, 0x68, 0x6F, 0x6E,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    //获取模块地址
    moduleBase = GetModuleBaseAddress(processID, targetModuleName);
    if (!moduleBase) {
        ErrorReporter::receive(ErrorReporter::严重, "无法找到模块基址");
        bad = true;
        return false;
    }
    qDebug() << "dll基址: " << Qt::hex << moduleBase;

    // 锚点扫描 (前 256MB)
    auto t = clock();
    anchorAddr = ScanRemoteAnchor(processHandle, moduleBase, SCAN_RANGE_BYTES, anchor, sizeof(anchor));
    if (!anchorAddr) {
        ErrorReporter::receive(ErrorReporter::严重, "无法找到锚点字符串");
        bad = true;
        return false;
    }
    qDebug()<<"锚点扫描用时"<<static_cast<float>(clock() - t)/CLOCKS_PER_SEC;
    qDebug() << "锚点地址 M: " << Qt::hex << anchorAddr;

    // struct_addr = M - 264, 解引用取 python_host
    uintptr_t structAddr = anchorAddr - ANCHOR_BACK_OFFSET;
    uintptr_t pythonHost = 0;
    if (!ReadProcessMemory(processHandle, (LPCVOID)structAddr, &pythonHost, sizeof(pythonHost),
                           nullptr)) {
        ErrorReporter::receive(ErrorReporter::严重, "无法读取python_host指针");
        qCritical()<<"读取"<<Qt::hex<<structAddr<<"失败："<<GetLastError();
        bad = true;
        return false;
    }
    if (!pythonHost) {
        ErrorReporter::receive(ErrorReporter::严重, "python_host为空(游戏可能尚未初始化)");
        bad = true;
        return false;
    }
    qDebug() << "python_host: " << Qt::hex << pythonHost;

    // frameIntervalAddr = pythonHost + 0x70
    frameIntervalAddr = pythonHost + HOST_FIELD_OFFSET;
    qInfo() << "帧间隔地址: " << Qt::hex << frameIntervalAddr;

    preframerateaddr = 0; // 新版逻辑不使用

    return true;
}

