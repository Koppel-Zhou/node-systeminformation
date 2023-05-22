#include <node_api.h>
#include <iostream>
#include <string>

#ifdef __APPLE__
#include <IOKit/IOKitLib.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <CoreGraphics/CoreGraphics.h>
#endif

#ifdef WIN32
#include <Windows.h>
#include <WinBase.h>
#include <intrin.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#endif

void TrimTail(char* source_str, char trim_char)
{
    if(NULL == source_str)
        return;

    // 从尾部开始跳过trim_char指定字符
    int source_str_len = strlen(source_str);
    char* source_str_point = source_str;
    int source_str_last_index = source_str_len - 1;
    while(source_str_last_index >= 0 && *(source_str_point + source_str_last_index) == trim_char)
        source_str_last_index--;

    // 计算新字符串长度并在结尾赋值为0
    source_str_len = source_str_last_index + 1;
    *(source_str+source_str_len) = 0;
}

napi_value GetDeviceUUID(napi_env env, napi_callback_info info) {
    napi_value result;
    std::string uuid = "";

#ifdef __APPLE__
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert) {
        CFStringRef uuidRef = (CFStringRef)IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
        if (uuidRef) {
            char buffer[128];
            CFStringGetCString(uuidRef, buffer, 128, kCFStringEncodingUTF8);
            uuid = buffer;
            CFRelease(uuidRef);
        }
        IOObjectRelease(platformExpert);
    }
#endif
#ifdef WIN32
    // FILE* stream = _popen("wmic csproduct get uuid", "r");
    // if (stream) {
    //     char buffer[128];
    //     if (fgets(buffer, 128, stream) != NULL) {
    //         if (fgets(buffer, 128, stream) != NULL) {
    //             TrimTail(buffer, char(10));   // 过滤尾部 \n
    //             TrimTail(buffer, char(13));   // 过滤尾部 \r
    //             TrimTail(buffer, char(32));   // 过滤尾部 空格
    //             uuid = buffer;
    //         }
    //     }
    //     _pclose(stream);
    // }
    IWbemServices* pSvc = NULL;
    IWbemLocator* pLoc = NULL;
    HRESULT hres;

    // 初始化 COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        napi_throw_error(env, NULL, "Failed to initialize COM");
        return NULL;
    }

    // 创建 WMI Locator 实例
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        napi_throw_error(env, NULL, "Failed to create IWbemLocator instance");
        return NULL;
    }

    // 连接 WMI
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        napi_throw_error(env, NULL, "Failed to connect to WMI");
        return NULL;
    }

    // 设置验证信息
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        napi_throw_error(env, NULL, "Failed to set proxy blanket");
        return NULL;
    }

    // 执行查询
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"), bstr_t("SELECT * FROM Win32_BaseBoard"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        napi_throw_error(env, NULL, "Failed to execute WQL query");
        return NULL;
    }

    // 获取查询结果
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) {
        break;
        }

        VARIANT vtProp;
        hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
        if (vtProp.vt == VT_NULL) {
            uuid = "";
        } else {
            uuid = _bstr_t(vtProp.bstrVal);
        }
        VariantClear(&vtProp);
        }

        pclsObj->Release();
    }

    // 释放资源
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
#endif

    napi_create_string_utf8(env, uuid.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetSerialNumber(napi_env env, napi_callback_info info) {
    napi_value result;
    std::string sn = "";

#ifdef __APPLE__
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert) {
        CFStringRef snRef = (CFStringRef)IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
        if (snRef) {
            char buffer[128];
            CFStringGetCString(snRef, buffer, 128, kCFStringEncodingUTF8);
            sn = buffer;
            CFRelease(snRef);
        }
        IOObjectRelease(platformExpert);
    }
#endif
#ifdef WIN32
    FILE* stream = _popen("wmic bios get serialnumber", "r");
    if (stream) {
        char buffer[128];
        if (fgets(buffer, 128, stream) != NULL) {
            if (fgets(buffer, 128, stream) != NULL) {
                TrimTail(buffer, char(10));   // 过滤尾部 \n
                TrimTail(buffer, char(13));   // 过滤尾部 \r
                TrimTail(buffer, char(32));   // 过滤尾部 空格
                sn = buffer;
            }
        }
        _pclose(stream);
    }
#endif

    napi_create_string_utf8(env, sn.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetSystemArch(napi_env env, napi_callback_info info) {
    napi_value result;
    std::string sys_arch = "";

#ifdef __APPLE__
    struct utsname name;
    if (uname(&name) == 0) {
        sys_arch = name.machine;
    }
    napi_create_string_utf8(env, sys_arch.c_str(), NAPI_AUTO_LENGTH, &result);
#endif
#ifdef WIN32
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        napi_create_string_utf8(env, "x64", NAPI_AUTO_LENGTH, &result);
    } else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        napi_create_string_utf8(env, "Itanium-based", NAPI_AUTO_LENGTH, &result);
    } else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) {
        napi_create_string_utf8(env, "ARM", NAPI_AUTO_LENGTH, &result);
    } else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        napi_create_string_utf8(env, "ARM64", NAPI_AUTO_LENGTH, &result);
    } else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        napi_create_string_utf8(env, "x86", NAPI_AUTO_LENGTH, &result);
    } else {
        napi_create_string_utf8(env, "Unknown", NAPI_AUTO_LENGTH, &result);
    }
#endif
    return result;
}

napi_value GetSystemVersion(napi_env env, napi_callback_info info) {
    napi_value result;
    std::string sys_version = "";

#ifdef __APPLE__
    size_t bufferSize = 0;
    sysctlbyname("kern.osproductversion", NULL, &bufferSize, NULL, 0);

    if (bufferSize > 0) {
        char *buffer = new char[bufferSize];
        sysctlbyname("kern.osproductversion", buffer, &bufferSize, NULL, 0);
        sys_version = std::string(buffer);
        delete[] buffer;
    }
#endif
#ifdef WIN32
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (GetVersionEx((OSVERSIONINFO *)&osvi)) {
        sys_version = std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion);
    }
#endif
    napi_create_string_utf8(env, sys_version.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetProductName(napi_env env, napi_callback_info info) {
    napi_value result;
    std::string prod_name = "";

#ifdef __APPLE__
    size_t bufferSize = 0;
    sysctlbyname("hw.model", NULL, &bufferSize, NULL, 0);

    if (bufferSize > 0) {
        char *buffer = new char[bufferSize];
        sysctlbyname("hw.model", buffer, &bufferSize, NULL, 0);
        prod_name = std::string(buffer);
        delete[] buffer;
    }
#endif
#ifdef WIN32
    FILE* stream = _popen("wmic csproduct get name", "r");
    if (stream) {
        char buffer[128];
        if (fgets(buffer, 128, stream) != NULL) {
            if (fgets(buffer, 128, stream) != NULL) {
                TrimTail(buffer, char(10));   // 过滤尾部 \n
                TrimTail(buffer, char(13));   // 过滤尾部 \r
                TrimTail(buffer, char(32));   // 过滤尾部 空格
                prod_name = buffer;
            }
        }
        _pclose(stream);
    }
#endif
    napi_create_string_utf8(env, prod_name.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetMemorySize(napi_env env, napi_callback_info info) {
    napi_value result;
    uint64_t memsize = 0;

#ifdef __APPLE__
    int mib[2];
    mib[0] = CTL_HW;
    mib[1] = HW_MEMSIZE;
    size_t length = sizeof(memsize);
    if (sysctl(mib, 2, &memsize, &length, NULL, 0) != 0) {
        napi_throw_error(env, NULL, "Failed to get memory size");
        return NULL;
    }
#endif
#ifdef WIN32
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    memsize = memInfo.ullTotalPhys;
#endif
    napi_create_int64(env, memsize, &result);
    return result;
}

napi_value GetCPUInfo(napi_env env, napi_callback_info info) {
    napi_value result;
    std::string cpu = "";

#ifdef __APPLE__
    size_t bufferSize = 0;
    sysctlbyname("machdep.cpu.brand_string", NULL, &bufferSize, NULL, 0);

    if (bufferSize > 0) {
        char *buffer = new char[bufferSize];
        sysctlbyname("machdep.cpu.brand_string", buffer, &bufferSize, NULL, 0);
        cpu = std::string(buffer);
        delete[] buffer;
    }
    napi_create_string_utf8(env, cpu.c_str(), NAPI_AUTO_LENGTH, &result);
#endif
#ifdef WIN32
    int cpuInfo[4] = {-1};
    __cpuid(cpuInfo, 0x80000002);
    char szBrand[48];
    memcpy(szBrand, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000003);
    memcpy(szBrand + 16, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000004);
    memcpy(szBrand + 32, cpuInfo, sizeof(cpuInfo));

    napi_create_string_utf8(env, szBrand, NAPI_AUTO_LENGTH, &result);
#endif
    return result;
}

napi_value GetScreenInfo(napi_env env, napi_callback_info info) {
    napi_value result, prop_width, prop_height;
    napi_status status = napi_generic_failure;
    status = napi_create_object(env, &result);
    uint32_t width = 0;
    uint32_t height = 0;
#ifdef __APPLE__
    CGDirectDisplayID displayId = CGMainDisplayID();
    width = CGDisplayPixelsWide(displayId);
    height = CGDisplayPixelsHigh(displayId);

#endif
#ifdef WIN32
    width = (int)GetSystemMetrics(SM_CXSCREEN);
    height = (int)GetSystemMetrics(SM_CYSCREEN);
#endif
    napi_create_uint32(env, width, &prop_width);
    napi_create_uint32(env, height, &prop_height);
    status = napi_set_named_property(env, result, "width", prop_width);
    if (status != napi_ok) return NULL;
    status = napi_set_named_property(env, result, "height", prop_height);
    if (status != napi_ok) return NULL;
    return result;
}

napi_value GetVendor(napi_env env, napi_callback_info info) {
    napi_value result;
    std::string manufacturer = "";

#ifdef __APPLE__
    std::string apple = "Apple Inc.";
    manufacturer = std::string(apple);
#endif
#ifdef WIN32
    FILE* stream = _popen("wmic csproduct get vendor", "r");
    if (stream) {
        char buffer[128];
        if (fgets(buffer, 128, stream) != NULL) {
            if (fgets(buffer, 128, stream) != NULL) {
                TrimTail(buffer, char(10));   // 过滤尾部 \n
                TrimTail(buffer, char(13));   // 过滤尾部 \r
                TrimTail(buffer, char(32));   // 过滤尾部 空格
                manufacturer = buffer;
            }
        }
        _pclose(stream);
    }
#endif

    napi_create_string_utf8(env, manufacturer.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor descriptors[] = {
        {"getUUID", 0, GetDeviceUUID, 0, 0, 0, napi_default, 0},
        {"getSerialNumber", 0, GetSerialNumber, 0, 0, 0, napi_default, 0},
        {"getSystemVersion", 0, GetSystemVersion, 0, 0, 0, napi_default, 0},
        {"getSystemArch", 0, GetSystemArch, 0, 0, 0, napi_default, 0},
        {"getProductName", 0, GetProductName, 0, 0, 0, napi_default, 0},
        {"getMemorySize", 0, GetMemorySize, 0, 0, 0, napi_default, 0},
        {"getCPUInfo", 0, GetCPUInfo, 0, 0, 0, napi_default, 0},
        {"getScreenInfo", 0, GetScreenInfo, 0, 0, 0, napi_default, 0},
        {"getVendor", 0, GetVendor, 0, 0, 0, napi_default, 0}
    };

    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(*descriptors), descriptors);
    return exports;
}

NAPI_MODULE(addon, Init)
