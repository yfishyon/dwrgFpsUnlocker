#ifndef FPS_SETTER_H
#define FPS_SETTER_H

#include <QDebug>

#include <windows.h>

/** 地址布局（新版 fps.exe 逻辑）
 *  neox_engine.dll 前 256MB 内扫描 16B 锚点 "python\0" + 10 个 \0
 *              ↓ anchorAddr = M
 *  [M - 264] → *(QWORD*) → python_host
 *                         → python_host + 0x70 → frameIntervalAddr (double 帧时长)
 */
class FpsSetter
{
protected:
    /* 最初写rcx+80的版本，麻烦IDE折叠一下
#define JMPLENTH 5
    static constexpr uintptr_t offset = 0x2525E0;
    static inline BYTE jumpInstruction[10] = {
        0xE9, 0x00, 0x00, 0x00, 0x00, //jmp <newMemoryAddress>
        0x90, 0x90, 0x90, 0x90, 0x90
    };
#define DFLT_FPS 60 //NOTE: 0-255, cuz 1 byte
#define FPS_OFFSET 3
#define ORIG_OFFSET 7
    static inline BYTE injectedCode[] = {
        0xC7, 0x42, 0x04, DFLT_FPS, 0x00, 0x00, 0x00, // mov dword ptr [rdx+4], 78
        0x0F, 0x10, 0x02,                         // movups xmm0, [rdx]
        0x0F, 0x11, 0x81, 0x88, 0x00, 0x00, 0x00, // movups [rcx+88h], xmm0
        0xE9, 0x00, 0x00, 0x00, 0x00
    };*/

//  static inline DWORD allocrice = 0;

    bool        bad;        //Setter是否可用
 // bool        fpsbad;     //fps是否可读取 / 我觉得无意义 --25.10.12
    bool        keepaccess; //是否自动关闭句柄
    DWORD       processID;
    HANDLE      processHandle;
    uintptr_t   moduleBase;
    uintptr_t   anchorAddr;          /* M: "python\0" 锚点匹配地址 */
    uintptr_t   frameIntervalAddr;    /* python_host + 0x70: 帧时长 double 写入地址 */
#define ANCHOR_BACK_OFFSET  264
#define HOST_FIELD_OFFSET   0x70
#define SCAN_RANGE_BYTES    0x10000000

    uintptr_t   preframerateaddr;    /* 保留兼容; 新版逻辑不使用 */
#define PFR_OFFSET       0x8
#define FR_OFFSET        0x23C

    friend class autoxtimerproxy;
    autoxtimerproxy* autoxprocesstimer;

public:
    /* 禁止拷贝的三-五，*/
    FpsSetter(DWORD pid);
    FpsSetter():bad(true), processHandle(NULL),autoxprocesstimer(nullptr), processID(0){}

    static FpsSetter create(DWORD pid = 0);

    FpsSetter(const FpsSetter&) = delete;
    FpsSetter& operator=(const FpsSetter&) = delete;

    FpsSetter(FpsSetter&& right) noexcept;
    FpsSetter& operator=(FpsSetter&& right) noexcept;

    ~FpsSetter();

explicit
    operator bool()const{return !bad;}

    DWORD getGamePID()const
    {
        return processID;
    }

    //读写前需要判断bad
    float getFps();
    bool setFps(int fps);

    //自动脱离(停止访问并释放句柄)
    void keepAccessible();
    void autoRelease();

protected:
    //获取内存地址
    bool getAddress();
    //打开或检查访问进程的句柄有效，否则返回false
    bool openHandle();
    void closeHandle();
    bool checkGameLiving();
    void bebad();

      /* 最初需要的分配jmp的就近x86地址的函数。麻烦IDE折叠一下
    LPVOID findnearfreememory(uintptr_t target_vmemaddr, size_t size)
    {
        LPVOID allocaddr = nullptr;

        static const uint32_t max_offset = (1LL<<32)/ *allocrice;
        uint64_t  l(target_vmemaddr/ *allocrice), r(target_vmemaddr/ *allocrice+max_offset);
//        do{
//            int64_t mid = (l&r) + ((l^r)>>1);
//            MEMORY_BASIC_INFORMATION pmbi;
//            auto retsize = VirtualQueryEx(*processHandle, (LPVOID)(mid**allocrice), &pmbi, sizeof(pmbi));
//            if (!(retsize == 0 || pmbi.State != MEM_FREE))
//            {
//                allocaddr = VirtualAllocEx(*processHandle, (LPVOID)(mid**allocrice), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//                if(allocaddr)
//                    return allocaddr;
//            }
//            r = mid;
//        }while (r != l);

        uint32_t granularity = max_offset;
        MEMORY_BASIC_INFORMATION mbi;
        while (granularity)
        {
            for (uint64_t i = l+granularity/2; i < r; i+=granularity)
            {
                auto retsize = VirtualQueryEx(processHandle, (LPVOID)(i**allocrice), &mbi, sizeof(mbi));
                if (!(retsize == 0 || mbi.State != MEM_FREE))
                {
                    allocaddr = VirtualAllocEx(processHandle, (LPVOID)(i**allocrice), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if(allocaddr)
                        return allocaddr;
                }
            }
            granularity /=2;
        }
        return nullptr;
    }*/
};

#endif // FPS_SETTER_H