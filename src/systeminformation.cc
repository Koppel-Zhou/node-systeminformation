#include <node_api.h>
#include <iostream>
#include <string>
#include <array>
#include <vector>

#ifdef __APPLE__
#include <IOKit/IOKitLib.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreAudio/CoreAudio.h>
#include <CoreMediaIO/CMIOHardware.h>
#include <CoreFoundation/CoreFoundation.h>
#include <cstdlib>
#include <IOKit/graphics/IOGraphicsLib.h>
#include <sys/param.h>
#include <sys/mount.h>
#endif

#ifdef WIN32
#include <Windows.h>
#include <WinBase.h>
#include <intrin.h>
#include <wbemidl.h>
#include <comutil.h>
#include <comdef.h>
#include <combaseapi.h>
#include <Objbase.h>
#include <WinError.h>
#include <propsys.h>
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#include <Functiondiscoverykeys_devpkey.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "propsys.lib")
#endif

#ifdef __APPLE__
bool IsVirtualAudioDevice(AudioDeviceID deviceId) {
    AudioObjectPropertyAddress propertyAddress;
    propertyAddress.mSelector = kAudioDevicePropertyStreams;
    propertyAddress.mScope = kAudioObjectPropertyScopeGlobal;
    propertyAddress.mElement = kAudioObjectPropertyElementWildcard;

    UInt32 propertySize = 0;
    OSStatus status = AudioObjectGetPropertyDataSize(deviceId, &propertyAddress, 0, NULL, &propertySize);
    if (status != noErr || propertySize == 0) {
        return false;
    }

    propertyAddress.mSelector = kAudioDevicePropertyTransportType;

    UInt32 transportType;
    propertySize = sizeof(transportType);
    status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &propertySize, &transportType);
    if (status != noErr) {
        return false;
    }

    return transportType == kAudioDeviceTransportTypeVirtual;
}

// Helper function to convert CFStringRef to std::string
std::string CFStringToString(CFStringRef cfString) {
    if (cfString == nullptr) {
        return "";
    }
    CFIndex bufferSize = CFStringGetLength(cfString) + 1;
    char buffer[bufferSize];
    if (!CFStringGetCString(cfString, buffer, bufferSize, kCFStringEncodingUTF8)) {
        return "";
    }
    return std::string(buffer);
}

std::string executeCommand(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "";
    }
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
            result += buffer.data();
        }
    }
    return result;
}

std::string extractChipsetModel(const std::string& output) {
    size_t startPos = output.find("Chipset Model: ");
    if (startPos == std::string::npos) {
        return "";
    }
    startPos += strlen("Chipset Model: ");

    size_t endPos = output.find('\n', startPos);
    if (endPos == std::string::npos) {
        return "";
    }

    return output.substr(startPos, endPos - startPos);
}
    
#endif

#ifdef WIN32
const CLSID CLSID_MMDeviceEnumerator = __uuidof(MMDeviceEnumerator);
const IID IID_IMMDeviceEnumerator = __uuidof(IMMDeviceEnumerator);

#define SAFE_RELEASE(punk) \
    if ((punk) != NULL)    \
    {                      \
        (punk)->Release(); \
        (punk) = NULL;     \
    }

char *ConvertLPWSTRToChar(LPCWSTR lpwstr)
{
    int size = WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, NULL, 0, NULL, NULL);
    char* buffer = new char[size];
    WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, buffer, size, NULL, NULL);
    return buffer;
}
// Helper function to convert BSTR to char*
char *ConvertBstrToChar(BSTR bstr)
{
    int length = SysStringLen(bstr);
    int size = WideCharToMultiByte(CP_UTF8, 0, bstr, length, NULL, 0, NULL, NULL);
    char *result = new char[size + 1];
    WideCharToMultiByte(CP_UTF8, 0, bstr, length, result, size, NULL, NULL);
    result[size] = '\0';
    return result;
}

// Helper function to convert VARIANT value to napi_value
napi_value ConvertVariantToValue(napi_env env, VARIANT &var)
{
    napi_value value;

    switch (var.vt)
    {
    case VT_I1:
    case VT_UI1:
        napi_create_int32(env, var.bVal, &value);
        break;
    case VT_I2:
    case VT_UI2:
        napi_create_int32(env, var.iVal, &value);
        break;
    case VT_I4:
    case VT_UI4:
        napi_create_int32(env, var.lVal, &value);
        break;
    case VT_I8:
    case VT_UI8:
        napi_create_double(env, static_cast<double>(var.llVal), &value);
        break;
    case VT_R4:
        napi_create_double(env, var.fltVal, &value);
        break;
    case VT_R8:
        napi_create_double(env, var.dblVal, &value);
        break;
    case VT_BOOL:
        napi_get_boolean(env, var.boolVal ? true : false, &value);
        break;
    case VT_BSTR:
    {
        char *str = ConvertBstrToChar(var.bstrVal);
        napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &value);
        delete[] str;
    }
    break;
    default:
        napi_get_undefined(env, &value);
        break;
    }

    return value;
}

const char *GetErrorMessageFromHRESULT(HRESULT hres)
{
    LPWSTR lpMsgBuf = NULL;
    DWORD result = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        hres,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf,
        0,
        NULL);

    if (result == 0)
    {
        return "Failed to get error message.";
    }

    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, lpMsgBuf, -1, NULL, 0, NULL, NULL);
    char *errorMessage = new char[bufferSize];
    WideCharToMultiByte(CP_UTF8, 0, lpMsgBuf, -1, errorMessage, bufferSize, NULL, NULL);

    LocalFree(lpMsgBuf);
    return errorMessage;
}
#endif

napi_value GetDeviceUUID(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string uuid = "";

#ifdef __APPLE__
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert)
    {
        CFStringRef uuidRef = (CFStringRef)IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
        if (uuidRef)
        {
            char buffer[128];
            CFStringGetCString(uuidRef, buffer, 128, kCFStringEncodingUTF8);
            uuid = buffer;
            CFRelease(uuidRef);
        }
        IOObjectRelease(platformExpert);
    }
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT UUID FROM Win32_ComputerSystemProduct"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;

    // Get the data from the query result
    hres = pEnumerator->Next(
        WBEM_INFINITE,
        1,
        &pclsObj,
        &uReturn);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    VARIANT vtProp;

    // Get the value of the UUID property
    hres = pclsObj->Get(L"UUID", 0, &vtProp, 0, 0);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pclsObj);
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Convert the UUID value to a string
    std::wstring uuid_buf = vtProp.bstrVal;
    int size = WideCharToMultiByte(CP_UTF8, 0, uuid_buf.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string uuidStr(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, uuid_buf.c_str(), -1, &uuidStr[0], size, nullptr, nullptr);

    uuid = uuidStr;

    // Clean up
    VariantClear(&vtProp);
    SAFE_RELEASE(pclsObj);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif

    napi_create_string_utf8(env, uuid.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetSerialNumber(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string sn = "";

#ifdef __APPLE__
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert)
    {
        CFStringRef snRef = (CFStringRef)IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
        if (snRef)
        {
            char buffer[128];
            CFStringGetCString(snRef, buffer, 128, kCFStringEncodingUTF8);
            sn = buffer;
            CFRelease(snRef);
        }
        IOObjectRelease(platformExpert);
    }
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;
    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT SerialNumber FROM Win32_Bios"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;

    // Get the data from the query result
    hres = pEnumerator->Next(
        WBEM_INFINITE,
        1,
        &pclsObj,
        &uReturn);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    VARIANT vtProp;

    // Get the value of the SerialNumber property
    hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pclsObj);
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Convert the SerialNumber value to a string
    std::wstring sn_buf = vtProp.bstrVal;
    int size = WideCharToMultiByte(CP_UTF8, 0, sn_buf.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string snStr(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, sn_buf.c_str(), -1, &snStr[0], size, nullptr, nullptr);

    sn = snStr;

    // Clean up
    VariantClear(&vtProp);
    SAFE_RELEASE(pclsObj);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif

    napi_create_string_utf8(env, sn.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetSystemArch(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string sys_arch = "";

#ifdef __APPLE__
    struct utsname name;
    if (uname(&name) == 0)
    {
        sys_arch = name.machine;
    }
    napi_create_string_utf8(env, sys_arch.c_str(), NAPI_AUTO_LENGTH, &result);
#endif
#ifdef WIN32
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
    {
        napi_create_string_utf8(env, "x64", NAPI_AUTO_LENGTH, &result);
    }
    else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
    {
        napi_create_string_utf8(env, "Itanium-based", NAPI_AUTO_LENGTH, &result);
    }
    else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM)
    {
        napi_create_string_utf8(env, "ARM", NAPI_AUTO_LENGTH, &result);
    }
    else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
    {
        napi_create_string_utf8(env, "ARM64", NAPI_AUTO_LENGTH, &result);
    }
    else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
    {
        napi_create_string_utf8(env, "x86", NAPI_AUTO_LENGTH, &result);
    }
    else
    {
        napi_create_string_utf8(env, "Unknown", NAPI_AUTO_LENGTH, &result);
    }
#endif
    return result;
}

napi_value GetSystemVersion(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string sys_version = "";
#ifdef __APPLE__
    // // The value obtained in this way will be affected by SYSTEM_VERSION_COMPAT, but it is faster
    // size_t bufferSize = 0;
    // sysctlbyname("kern.osproductversion", NULL, &bufferSize, NULL, 0);

    // if (bufferSize > 0)
    // {
    //     char *buffer = new char[bufferSize];
    //     sysctlbyname("kern.osproductversion", buffer, &bufferSize, NULL, 0);
    //     sys_version = std::string(buffer);
    //     delete[] buffer;
    // }

    std::string command = "sw_vers -ProductVersion";
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe) {
        char buffer[128];
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != nullptr)
                sys_version += buffer;
        }
        pclose(pipe);
    }

    if (!sys_version.empty() && sys_version[sys_version.length() - 1] == '\n') {
        sys_version.erase(sys_version.length() - 1);
    }
#endif
#ifdef WIN32
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    
    if (GetVersionExA((OSVERSIONINFOA*)&osvi) != 0) {
        sys_version =
        std::to_string(osvi.dwMajorVersion)
        + "." + std::to_string(osvi.dwMinorVersion)
        + "." + std::to_string(osvi.dwBuildNumber);

        if (osvi.wServicePackMajor != 0 || osvi.wServicePackMinor != 0) {
            sys_version = sys_version
            + " Service Pack "
            + std::to_string(osvi.wServicePackMajor)
            + "." + std::to_string(osvi.wServicePackMinor);
        }
    }
#endif
    napi_create_string_utf8(env, sys_version.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetProductName(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string prod_name = "";

#ifdef __APPLE__
    size_t bufferSize = 0;
    sysctlbyname("hw.model", NULL, &bufferSize, NULL, 0);

    if (bufferSize > 0)
    {
        char *buffer = new char[bufferSize];
        sysctlbyname("hw.model", buffer, &bufferSize, NULL, 0);
        prod_name = std::string(buffer);
        delete[] buffer;
    }
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }


    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name FROM Win32_ComputerSystemProduct"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;

    // Get the data from the query result
    hres = pEnumerator->Next(
        WBEM_INFINITE,
        1,
        &pclsObj,
        &uReturn);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    VARIANT vtProp;

    // Get the value of the Name property
    hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pclsObj);
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Convert the Name value to a string
    std::wstring name_buf = vtProp.bstrVal;
    int size = WideCharToMultiByte(CP_UTF8, 0, name_buf.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string nameStr(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, name_buf.c_str(), -1, &nameStr[0], size, nullptr, nullptr);

    prod_name = nameStr;

    // Clean up
    VariantClear(&vtProp);
    SAFE_RELEASE(pclsObj);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif
    napi_create_string_utf8(env, prod_name.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetMemorySize(napi_env env, napi_callback_info info)
{
    napi_value result;
    uint64_t memsize = 0;

#ifdef __APPLE__
    int mib[2];
    mib[0] = CTL_HW;
    mib[1] = HW_MEMSIZE;
    size_t length = sizeof(memsize);
    if (sysctl(mib, 2, &memsize, &length, NULL, 0) != 0)
    {
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

napi_value GetCPU(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string cpu = "";

#ifdef __APPLE__
    size_t bufferSize = 0;
    sysctlbyname("machdep.cpu.brand_string", NULL, &bufferSize, NULL, 0);

    if (bufferSize > 0)
    {
        char *buffer = new char[bufferSize];
        sysctlbyname("machdep.cpu.brand_string", buffer, &bufferSize, NULL, 0);
        cpu = std::string(buffer);
        delete[] buffer;
    }
    napi_create_string_utf8(env, cpu.c_str(), NAPI_AUTO_LENGTH, &result);
#endif
#ifdef WIN32
    // // This method cannot get the correct value on the Microsoft Surface device
    // int cpuInfo[4] = {-1};
    // __cpuid(cpuInfo, 0x80000002);
    // char szBrand[48];
    // memcpy(szBrand, cpuInfo, sizeof(cpuInfo));

    // __cpuid(cpuInfo, 0x80000003);
    // memcpy(szBrand + 16, cpuInfo, sizeof(cpuInfo));

    // __cpuid(cpuInfo, 0x80000004);
    // memcpy(szBrand + 32, cpuInfo, sizeof(cpuInfo));

    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;

    // Get the data from the query result
    hres = pEnumerator->Next(
        WBEM_INFINITE,
        1,
        &pclsObj,
        &uReturn);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    VARIANT vtProp;

    // Get the value of the CPU property
    hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pclsObj);
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Convert the CPU value to a string
    std::string cpuStr = "";
    cpuStr = _com_util::ConvertBSTRToString(vtProp.bstrVal);

    napi_create_string_utf8(env, cpuStr.c_str(), NAPI_AUTO_LENGTH, &result);

    // Clean up
    VariantClear(&vtProp);
    SAFE_RELEASE(pclsObj);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif
    return result;
}

napi_value GetScreenInfo(napi_env env, napi_callback_info info)
{
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
    if (status != napi_ok)
        return NULL;
    status = napi_set_named_property(env, result, "height", prop_height);
    if (status != napi_ok)
        return NULL;
    return result;
}

napi_value GetVendor(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string manufacturer = "";

#ifdef __APPLE__
    std::string apple = "Apple Inc.";
    manufacturer = std::string(apple);
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Vendor FROM Win32_ComputerSystemProduct"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;

    // Get the data from the query result
    hres = pEnumerator->Next(
        WBEM_INFINITE,
        1,
        &pclsObj,
        &uReturn);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    VARIANT vtProp;

    // Get the value of the Vendor property
    hres = pclsObj->Get(L"Vendor", 0, &vtProp, 0, 0);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pclsObj);
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Convert the Vendor value to a string
    std::wstring vendor_buf = vtProp.bstrVal;
    int size = WideCharToMultiByte(CP_UTF8, 0, vendor_buf.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string vendorStr(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, vendor_buf.c_str(), -1, &vendorStr[0], size, nullptr, nullptr);

    manufacturer = vendorStr;

    // Clean up
    VariantClear(&vtProp);
    SAFE_RELEASE(pclsObj);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif

    napi_create_string_utf8(env, manufacturer.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetCaption(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string caption = "";

#ifdef __APPLE__
    // // The value obtained in this way will be affected by SYSTEM_VERSION_COMPAT, but it is faster
    // CFStringRef filePath = CFSTR("/System/Library/CoreServices/SystemVersion.plist");
    // CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, filePath, kCFURLPOSIXPathStyle, false);
    // CFReadStreamRef fileStream = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);
    // CFRelease(fileURL);

    // if (fileStream) {
    //     CFReadStreamOpen(fileStream);
    //     CFPropertyListFormat format;
    //     CFErrorRef error;
    //     CFPropertyListRef plist = CFPropertyListCreateWithStream(kCFAllocatorDefault, fileStream, 0, kCFPropertyListImmutable, &format, &error);

    //     if (plist && format == kCFPropertyListXMLFormat_v1_0) {
    //         CFDictionaryRef dict = static_cast<CFDictionaryRef>(plist);
    //         CFStringRef productName = static_cast<CFStringRef>(CFDictionaryGetValue(dict, CFSTR("ProductName")));
    //         CFStringRef productVersion = static_cast<CFStringRef>(CFDictionaryGetValue(dict, CFSTR("ProductVersion")));

    //         if (productName && productVersion) {
    //             CFIndex length = CFStringGetLength(productName) + CFStringGetLength(productVersion);
    //             CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
    //             char* buffer = new char[maxSize];
    //             if (CFStringGetCString(productName, buffer, maxSize, kCFStringEncodingUTF8)) {
    //                 caption = buffer;
    //             }
    //             if (CFStringGetCString(productVersion, buffer, maxSize, kCFStringEncodingUTF8)) {
    //                 caption += " ";
    //                 caption += buffer;
    //             }
    //             delete[] buffer;
    //         }
    //     }

    //     CFRelease(plist);
    //     CFReadStreamClose(fileStream);
    //     CFRelease(fileStream);
    // }

    std::string nameCommand = "sw_vers -ProductName";
    std::string name = "";
    FILE* name_pipe = popen(nameCommand.c_str(), "r");
    if (name_pipe) {
        char buffer[128];
        while (!feof(name_pipe)) {
            if (fgets(buffer, 128, name_pipe) != nullptr)
                name += buffer;
        }
        pclose(name_pipe);
    }

    if (!name.empty() && name[name.length() - 1] == '\n') {
        name.erase(name.length() - 1);
    }

    std::string versionCommand = "sw_vers -ProductVersion";
    std::string version = "";
    FILE* version_pipe = popen(versionCommand.c_str(), "r");
    if (version_pipe) {
        char buffer[128];
        while (!feof(version_pipe)) {
            if (fgets(buffer, 128, version_pipe) != nullptr)
                version += buffer;
        }
        pclose(version_pipe);
    }

    if (!version.empty() && version[version.length() - 1] == '\n') {
        version.erase(version.length() - 1);
    }
    caption = name + " " + version;
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Caption FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;

    // Get the data from the query result
    hres = pEnumerator->Next(
        WBEM_INFINITE,
        1,
        &pclsObj,
        &uReturn);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    VARIANT vtProp;

    // Get the value of the Vendor property
    hres = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pclsObj);
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Convert the Caption value to a string
    std::wstring caption_buf = vtProp.bstrVal;
    int size = WideCharToMultiByte(CP_UTF8, 0, caption_buf.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string captionStr(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, caption_buf.c_str(), -1, &captionStr[0], size, nullptr, nullptr);

    caption = captionStr;

    // Clean up
    VariantClear(&vtProp);
    SAFE_RELEASE(pclsObj);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif

    napi_create_string_utf8(env, caption.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetAudioDevices(napi_env env, napi_callback_info info)
{
    napi_value result;
    napi_create_array(env, &result);
#ifdef __APPLE__
    UInt32 propertySize;
    AudioDeviceID deviceId;
    AudioObjectPropertyAddress propertyAddress;
    propertyAddress.mSelector = kAudioHardwarePropertyDevices;
    propertyAddress.mScope = kAudioObjectPropertyScopeGlobal;
    propertyAddress.mElement = kAudioObjectPropertyElementWildcard;

    OSStatus status = AudioObjectGetPropertyDataSize(kAudioObjectSystemObject, &propertyAddress, 0, NULL, &propertySize);
    if (status != noErr) {
        napi_throw_error(env, NULL, "Failed to get audio device list size");
        return result;
    }

    int deviceCount = propertySize / sizeof(AudioDeviceID);
    AudioDeviceID *deviceIds = new AudioDeviceID[deviceCount];

    status = AudioObjectGetPropertyData(kAudioObjectSystemObject, &propertyAddress, 0, NULL, &propertySize, deviceIds);
    if (status != noErr) {
        napi_throw_error(env, NULL, "Failed to get audio device list");
        delete[] deviceIds;
        return result;
    }

    int j = 0;  // Index for physical microphone devices
    for (int i = 0; i < deviceCount; i++) {
        deviceId = deviceIds[i];
        napi_value deviceInfo;
        napi_create_object(env, &deviceInfo);
        
        if (IsVirtualAudioDevice(deviceId)) {
            continue;
        }
        // get id
        napi_value idValue;
        napi_create_uint32(env, deviceId, &idValue);
        napi_set_named_property(env, deviceInfo, "id", idValue);

        // get name
        propertyAddress.mSelector = kAudioObjectPropertyName;

        CFStringRef deviceName;
        propertySize = sizeof(deviceName);

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &propertySize, &deviceName);
        if (status != noErr) {
            continue;
        }

        char deviceNameStr[256];
        CFStringGetCString(deviceName, deviceNameStr, sizeof(deviceNameStr), kCFStringEncodingUTF8);
        CFRelease(deviceName);

        napi_value nameValue;
        napi_create_string_utf8(env, deviceNameStr, NAPI_AUTO_LENGTH, &nameValue);
        napi_set_named_property(env, deviceInfo, "name", nameValue);

        // get manufacturer
        propertyAddress.mSelector = kAudioObjectPropertyManufacturer;

        CFStringRef manufacturer;
        propertySize = sizeof(manufacturer);

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &propertySize, &manufacturer);
        if (status != noErr) {
            continue;
        }

        char manufacturerStr[256];
        CFStringGetCString(manufacturer, manufacturerStr, sizeof(manufacturerStr), kCFStringEncodingUTF8);
        CFRelease(manufacturer);

        napi_value manufacturerValue;
        napi_create_string_utf8(env, manufacturerStr, NAPI_AUTO_LENGTH, &manufacturerValue);
        napi_set_named_property(env, deviceInfo, "manufacturer", manufacturerValue);

        napi_set_element(env, result, j++, deviceInfo);
    }

    delete[] deviceIds;
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        // _bstr_t(L"SELECT * FROM Win32_SoundDevice"),
        _bstr_t(L"SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'AudioEndpoint'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    ULONG uReturned;
    napi_value device;
    int index = 0;

    // Enumerate through audio devices and add them to the result array
    while (true)
    {
        IWbemClassObject *pSoundDevice = NULL;

        // Get the next audio device
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pSoundDevice, &uReturned);
        if (hres == WBEM_S_FALSE || uReturned == 0)
            break;

        // Get the name of the audio device
        VARIANT var;
        hres = pSoundDevice->Get(L"Availability", 0, &var, 0, 0);
        if (SUCCEEDED(hres))
        {
            napi_create_object(env, &device);

            // Get additional properties of the audio device
            const LPCWSTR properties[] = {
                L"Availability",
                L"Caption",
                L"ConfigManagerErrorCode",
                L"ConfigManagerUserConfig",
                L"CreationClassName",
                L"Description",
                L"DeviceID",
                L"DMABufferSize",
                L"ErrorCleared",
                L"ErrorDescription",
                L"InstallDate",
                L"LastErrorCode",
                L"Manufacturer",
                L"MPU401Address",
                L"Name",
                L"PNPDeviceID",
                L"PowerManagementCapabilities[]",
                L"PowerManagementSupported",
                L"ProductName",
                L"Status",
                L"StatusInfo",
                L"SystemCreationClassName",
                L"SystemName"};
            const char *propertyNames[] = {
                "Availability",
                "Caption",
                "ConfigManagerErrorCode",
                "ConfigManagerUserConfig",
                "CreationClassName",
                "Description",
                "DeviceID",
                "DMABufferSize",
                "ErrorCleared",
                "ErrorDescription",
                "InstallDate",
                "LastErrorCode",
                "Manufacturer",
                "MPU401Address",
                "Name",
                "PNPDeviceID",
                "PowerManagementCapabilities[]",
                "PowerManagementSupported",
                "ProductName",
                "Status",
                "StatusInfo",
                "SystemCreationClassName",
                "SystemName"};
            const int numProperties = sizeof(properties) / sizeof(properties[0]);

            for (int i = 0; i < numProperties; i++)
            {
                hres = pSoundDevice->Get(properties[i], 0, &var, 0, 0);
                if (SUCCEEDED(hres))
                {
                    napi_value propName;
                    napi_value propValue;
                    napi_create_string_utf8(env, propertyNames[i], NAPI_AUTO_LENGTH, &propName);
                    propValue = ConvertVariantToValue(env, var);
                    napi_set_property(env, device, propName, propValue);
                    VariantClear(&var);
                }
            }

            // Add the video device to the result array
            napi_set_element(env, result, index, device);

            ++index;

            VariantClear(&var);
        }

        SAFE_RELEASE(pSoundDevice);
    }

    // Clean up
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif
    return result;
}

napi_value GetVideoDevices(napi_env env, napi_callback_info info)
{
    napi_value result;
    napi_create_array(env, &result);
#ifdef __APPLE__
    // Get the list of cameras using CMIOObjectGetPropertyData
    CMIOObjectPropertyAddress propAddress;
    propAddress.mSelector = kCMIOHardwarePropertyDevices;
    propAddress.mScope = kCMIOObjectPropertyScopeGlobal;
    propAddress.mElement = kCMIOObjectPropertyElementMaster;

    UInt32 dataSize = 0;
    OSStatus err = CMIOObjectGetPropertyDataSize(kCMIOObjectSystemObject, &propAddress, 0, nullptr, &dataSize);
    if (err != noErr) {
        napi_throw_error(env, nullptr, "Failed to get camera list size");
        return nullptr;
    }

    UInt32 deviceCount = dataSize / sizeof(CMIODeviceID);
    std::vector<CMIODeviceID> deviceList(deviceCount);
    err = CMIOObjectGetPropertyData(kCMIOObjectSystemObject, &propAddress, 0, nullptr, dataSize, &deviceCount, deviceList.data());
    if (err != noErr) {
        napi_throw_error(env, nullptr, "Failed to get camera list");
        return nullptr;
    }

    for (UInt32 i = 0; i < deviceCount; i++) {
        CMIODeviceID deviceId = deviceList[i];
    
        napi_value cameraObject;
        napi_create_object(env, &cameraObject);

        napi_value idProp;
        napi_create_uint32(env, deviceId, &idProp);
        napi_set_named_property(env, cameraObject, "id", idProp);
        // Get the device name
        propAddress.mSelector = kCMIOObjectPropertyName;

        CFStringRef nameStringRef;
        dataSize = sizeof(nameStringRef);
        err = CMIOObjectGetPropertyData(deviceId, &propAddress, 0, nullptr, dataSize, &dataSize, &nameStringRef);
        if (err != noErr) {
            continue;
        }

        // Convert CFStringRef to C string
        char nameBuffer[256];
        CFStringGetCString(nameStringRef, nameBuffer, sizeof(nameBuffer), kCFStringEncodingUTF8);
        CFRelease(nameStringRef);

        napi_value nameProp;
        napi_create_string_utf8(env, nameBuffer, NAPI_AUTO_LENGTH, &nameProp);
        napi_set_named_property(env, cameraObject, "name", nameProp);

        propAddress.mSelector = kCMIODevicePropertyModelUID;

        CFStringRef modeUIDRef;
        dataSize = sizeof(modeUIDRef);
        err = CMIOObjectGetPropertyData(deviceId, &propAddress, 0, nullptr, dataSize, &dataSize, &modeUIDRef);
        if (err != noErr) {
            continue;
        }

        // Convert CFStringRef to C string
        char modeUIDBuffer[256];
        CFStringGetCString(modeUIDRef, modeUIDBuffer, sizeof(modeUIDBuffer), kCFStringEncodingUTF8);
        CFRelease(modeUIDRef);

        napi_value modeUIDProp;
        napi_create_string_utf8(env, modeUIDBuffer, NAPI_AUTO_LENGTH, &modeUIDProp);
        napi_set_named_property(env, cameraObject, "modeUID", modeUIDProp);

        // Add the camera object to the array
        napi_set_element(env, result, i, cameraObject);
    }
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'Camera' OR PNPClass = 'Image'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    ULONG uReturned;
    napi_value device;
    int index = 0;

    // Enumerate through video devices and add them to the result array
    while (true)
    {
        IWbemClassObject *pPnPEntityDevice = NULL;

        // Get the next video device
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pPnPEntityDevice, &uReturned);
        if (hres == WBEM_S_FALSE || uReturned == 0)
            break;

        // Get the name of the video device
        VARIANT var;
        hres = pPnPEntityDevice->Get(L"Availability", 0, &var, 0, 0);
        if (SUCCEEDED(hres))
        {
            napi_create_object(env, &device);

            // Get additional properties of the video device
            const LPCWSTR properties[] = {
                L"Availability",
                L"Caption",
                L"ClassGuid",
                L"CompatibleID[]",
                L"ConfigManagerErrorCode",
                L"ConfigManagerUserConfig",
                L"CreationClassName",
                L"Description",
                L"DeviceID",
                L"ErrorCleared",
                L"ErrorDescription",
                L"HardwareID[]",
                L"InstallDate",
                L"LastErrorCode",
                L"Manufacturer",
                L"Name",
                L"PNPClass",
                L"PNPDeviceID",
                L"PowerManagementCapabilities[]",
                L"PowerManagementSupported",
                L"Present",
                L"Service",
                L"Status",
                L"StatusInfo",
                L"SystemCreationClassName",
                L"SystemName"};
            const char *propertyNames[] = {
                "Availability",
                "Caption",
                "ClassGuid",
                "CompatibleID[]",
                "ConfigManagerErrorCode",
                "ConfigManagerUserConfig",
                "CreationClassName",
                "Description",
                "DeviceID",
                "ErrorCleared",
                "ErrorDescription",
                "HardwareID[]",
                "InstallDate",
                "LastErrorCode",
                "Manufacturer",
                "Name",
                "PNPClass",
                "PNPDeviceID",
                "PowerManagementCapabilities[]",
                "PowerManagementSupported",
                "Present",
                "Service",
                "Status",
                "StatusInfo",
                "SystemCreationClassName",
                "SystemName"};
            const int numProperties = sizeof(properties) / sizeof(properties[0]);

            for (int i = 0; i < numProperties; i++)
            {
                hres = pPnPEntityDevice->Get(properties[i], 0, &var, 0, 0);
                if (SUCCEEDED(hres))
                {
                    napi_value propName;
                    napi_value propValue;
                    napi_create_string_utf8(env, propertyNames[i], NAPI_AUTO_LENGTH, &propName);
                    propValue = ConvertVariantToValue(env, var);
                    napi_set_property(env, device, propName, propValue);
                    VariantClear(&var);
                }
            }

            // Add the video device to the result array
            napi_set_element(env, result, index, device);

            ++index;

            VariantClear(&var);
        }

        SAFE_RELEASE(pPnPEntityDevice);
    }

    // Clean up
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif
    return result;
}

// get Speaker
napi_value GetSpeakerDevices(napi_env env, napi_callback_info info)
{
    napi_value result;
    napi_create_array(env, &result);
#ifdef __APPLE__
    UInt32 propertySize;
    AudioDeviceID deviceId;
    AudioObjectPropertyAddress propertyAddress;
    propertyAddress.mSelector = kAudioHardwarePropertyDevices;
    propertyAddress.mScope = kAudioObjectPropertyScopeOutput;
    propertyAddress.mElement = kAudioObjectPropertyElementWildcard;

    OSStatus status = AudioObjectGetPropertyDataSize(kAudioObjectSystemObject, &propertyAddress, 0, NULL, &propertySize);
    if (status != noErr) {
        napi_throw_error(env, NULL, "Failed to get audio device list size");
        return result;
    }

    int deviceCount = propertySize / sizeof(AudioDeviceID);
    AudioDeviceID *deviceIds = new AudioDeviceID[deviceCount];

    status = AudioObjectGetPropertyData(kAudioObjectSystemObject, &propertyAddress, 0, NULL, &propertySize, deviceIds);
    if (status != noErr) {
        napi_throw_error(env, NULL, "Failed to get audio device list");
        delete[] deviceIds;
        return result;
    }

    int j = 0;  // Index for physical microphone devices
    for (int i = 0; i < deviceCount; i++) {
        deviceId = deviceIds[i];
        napi_value deviceInfo;
        napi_create_object(env, &deviceInfo);
        
        if (IsVirtualAudioDevice(deviceId)) {
            continue;
        }

        UInt32 dataSize = 0;
        propertyAddress.mSelector = kAudioDevicePropertyStreamConfiguration;
        status = AudioObjectGetPropertyDataSize(deviceId, &propertyAddress, 0, NULL, &dataSize);
        if (status != noErr) {
            continue;
        }

        AudioBufferList *bufferList = (AudioBufferList *)(malloc(dataSize));
        if (NULL == bufferList) {
            continue;
        }

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &dataSize, bufferList);
        if (status != noErr || 0 == bufferList->mNumberBuffers) {
            free(bufferList);
            bufferList = NULL;
            continue;
        }

        free(bufferList);
        bufferList = NULL;

        // get id
        napi_value idValue;
        napi_create_uint32(env, deviceId, &idValue);
        napi_set_named_property(env, deviceInfo, "id", idValue);

        // get name
        propertyAddress.mSelector = kAudioObjectPropertyName;

        CFStringRef deviceName;
        propertySize = sizeof(deviceName);

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &propertySize, &deviceName);
        if (status != noErr) {
            continue;
        }

        char deviceNameStr[256];
        CFStringGetCString(deviceName, deviceNameStr, sizeof(deviceNameStr), kCFStringEncodingUTF8);
        CFRelease(deviceName);

        napi_value nameValue;
        napi_create_string_utf8(env, deviceNameStr, NAPI_AUTO_LENGTH, &nameValue);
        napi_set_named_property(env, deviceInfo, "name", nameValue);

        // get manufacturer
        propertyAddress.mSelector = kAudioObjectPropertyManufacturer;

        CFStringRef manufacturer;
        propertySize = sizeof(manufacturer);

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &propertySize, &manufacturer);
        if (status != noErr) {
            continue;
        }

        char manufacturerStr[256];
        CFStringGetCString(manufacturer, manufacturerStr, sizeof(manufacturerStr), kCFStringEncodingUTF8);
        CFRelease(manufacturer);

        napi_value manufacturerValue;
        napi_create_string_utf8(env, manufacturerStr, NAPI_AUTO_LENGTH, &manufacturerValue);
        napi_set_named_property(env, deviceInfo, "manufacturer", manufacturerValue);
        
        napi_set_element(env, result, j++, deviceInfo);
    }

    delete[] deviceIds;
#endif
#ifdef WIN32
    HRESULT hres = S_OK;
    IMMDeviceEnumerator *pEnumerator = NULL;
    IMMDeviceCollection *pCollection = NULL;
    IMMDevice *pEndpoint = NULL;
    IPropertyStore *pProps = NULL;
    LPWSTR pwszID = NULL;
    UINT count = 0;

#define EXIT_ON_ERROR(hres) \
    if (FAILED(hres))       \
    {                       \
        goto Exit;          \
    }

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }


    hres = CoCreateInstance(
        CLSID_MMDeviceEnumerator, NULL,
        CLSCTX_ALL, IID_IMMDeviceEnumerator,
        (void **)&pEnumerator);
    EXIT_ON_ERROR(hres);

    hres = pEnumerator->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE, &pCollection);
    EXIT_ON_ERROR(hres);

    hres = pCollection->GetCount(&count);
    EXIT_ON_ERROR(hres);

    if (count == 0)
    {
        return result;
    }
    // Each loop the PKEY of an endpoint device.
    for (ULONG i = 0; i < count; i++)
    {
        napi_value device;
        napi_create_object(env, &device);
        // Get pointer to endpoint number i.
        hres = pCollection->Item(i, &pEndpoint);
        EXIT_ON_ERROR(hres);

        // Get the endpoint ID string.
        hres = pEndpoint->GetId(&pwszID);
        EXIT_ON_ERROR(hres);

        char *str = ConvertLPWSTRToChar(pwszID);
        napi_value propName;
        napi_value propValue;
        napi_create_string_utf8(env, "PKEY_Device_InstanceId", NAPI_AUTO_LENGTH, &propName);
        napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
        napi_set_property(env, device, propName, propValue);

        hres = pEndpoint->OpenPropertyStore(STGM_READ, &pProps);
        EXIT_ON_ERROR(hres);

        PROPVARIANT varName;
        // Initialize container for property value.
        PropVariantInit(&varName);

        // Get the endpoint's friendly-name property.
        hres = pProps->GetValue(PKEY_DeviceInterface_FriendlyName, &varName);
        EXIT_ON_ERROR(hres);

        // GetValue succeeds and returns S_OK if PKEY_DeviceInterface_FriendlyName is not found.
        // In this case vartName.vt is set to VT_EMPTY.
        if (varName.vt != VT_EMPTY)
        {
            char *str = ConvertLPWSTRToChar(varName.pwszVal);

            napi_value propName;
            napi_value propValue;
            napi_create_string_utf8(env, "PKEY_DeviceInterface_FriendlyName", NAPI_AUTO_LENGTH, &propName);
            napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
            napi_set_property(env, device, propName, propValue);
        };

        // Get the endpoint's friendly-name property.
        hres = pProps->GetValue(PKEY_Device_DeviceDesc, &varName);
        EXIT_ON_ERROR(hres);

        // GetValue succeeds and returns S_OK if PKEY_Device_DeviceDesc is not found.
        // In this case vartName.vt is set to VT_EMPTY.
        if (varName.vt != VT_EMPTY)
        {
            char *str = ConvertLPWSTRToChar(varName.pwszVal);

            napi_value propName;
            napi_value propValue;
            napi_create_string_utf8(env, "PKEY_Device_DeviceDesc", NAPI_AUTO_LENGTH, &propName);
            napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
            napi_set_property(env, device, propName, propValue);
        };

        // Get the endpoint's friendly-name property.
        hres = pProps->GetValue(PKEY_Device_FriendlyName, &varName);
        EXIT_ON_ERROR(hres);

        // GetValue succeeds and returns S_OK if PKEY_Device_FriendlyName is not found.
        // In this case vartName.vt is set to VT_EMPTY.
        if (varName.vt != VT_EMPTY)
        {
            char *str = ConvertLPWSTRToChar(varName.pwszVal);

            napi_value propName;
            napi_value propValue;
            napi_create_string_utf8(env, "PKEY_Device_FriendlyName", NAPI_AUTO_LENGTH, &propName);
            napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
            napi_set_property(env, device, propName, propValue);
        };

        napi_set_element(env, result, i, device);

        CoTaskMemFree(pwszID);
        pwszID = NULL;
        PropVariantClear(&varName);
        SAFE_RELEASE(pEndpoint);
        SAFE_RELEASE(pProps);
    }

Exit:
    CoTaskMemFree(pwszID);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pCollection);
    SAFE_RELEASE(pEndpoint);
    SAFE_RELEASE(pProps);
    CoUninitialize();
#endif
    return result;
}

// get Microphone
napi_value GetMicrophoneDevices(napi_env env, napi_callback_info info)
{
    napi_value result;
    napi_create_array(env, &result);
#ifdef __APPLE__
    UInt32 propertySize;
    AudioDeviceID deviceId;
    AudioObjectPropertyAddress propertyAddress;
    propertyAddress.mSelector = kAudioHardwarePropertyDevices;
    propertyAddress.mScope = kAudioObjectPropertyScopeInput;
    propertyAddress.mElement = kAudioObjectPropertyElementWildcard;

    OSStatus status = AudioObjectGetPropertyDataSize(kAudioObjectSystemObject, &propertyAddress, 0, NULL, &propertySize);
    if (status != noErr) {
        return result;
    }

    int deviceCount = propertySize / sizeof(AudioDeviceID);
    AudioDeviceID *deviceIds = new AudioDeviceID[deviceCount];

    status = AudioObjectGetPropertyData(kAudioObjectSystemObject, &propertyAddress, 0, NULL, &propertySize, deviceIds);
    if (status != noErr) {
        delete[] deviceIds;
        return result;
    }

    int j = 0;  // Index for physical microphone devices
    for (int i = 0; i < deviceCount; i++) {
        deviceId = deviceIds[i];
        napi_value deviceInfo;
        napi_create_object(env, &deviceInfo);
        
        if (IsVirtualAudioDevice(deviceId)) {
            continue;
        }

        UInt32 dataSize = 0;
        propertyAddress.mSelector = kAudioDevicePropertyStreamConfiguration;
        status = AudioObjectGetPropertyDataSize(deviceId, &propertyAddress, 0, NULL, &dataSize);
        if (status != noErr) {
            continue;
        }

        AudioBufferList *bufferList = (AudioBufferList *)(malloc(dataSize));
        if (NULL == bufferList) {
            continue;
        }

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &dataSize, bufferList);
        if (status != noErr || 0 == bufferList->mNumberBuffers) {
            free(bufferList);
            bufferList = NULL;
            continue;
        }

        free(bufferList);
        bufferList = NULL;

        // get id
        napi_value idValue;
        napi_create_uint32(env, deviceId, &idValue);
        napi_set_named_property(env, deviceInfo, "id", idValue);

        // get name
        propertyAddress.mSelector = kAudioObjectPropertyName;

        CFStringRef deviceName;
        propertySize = sizeof(deviceName);

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &propertySize, &deviceName);
        if (status != noErr) {
            continue;
        }

        char deviceNameStr[256];
        CFStringGetCString(deviceName, deviceNameStr, sizeof(deviceNameStr), kCFStringEncodingUTF8);
        CFRelease(deviceName);

        napi_value nameValue;
        napi_create_string_utf8(env, deviceNameStr, NAPI_AUTO_LENGTH, &nameValue);
        napi_set_named_property(env, deviceInfo, "name", nameValue);

        // get manufacturer
        propertyAddress.mSelector = kAudioObjectPropertyManufacturer;

        CFStringRef manufacturer;
        propertySize = sizeof(manufacturer);

        status = AudioObjectGetPropertyData(deviceId, &propertyAddress, 0, NULL, &propertySize, &manufacturer);
        if (status != noErr) {
            continue;
        }

        char manufacturerStr[256];
        CFStringGetCString(manufacturer, manufacturerStr, sizeof(manufacturerStr), kCFStringEncodingUTF8);
        CFRelease(manufacturer);

        napi_value manufacturerValue;
        napi_create_string_utf8(env, manufacturerStr, NAPI_AUTO_LENGTH, &manufacturerValue);
        napi_set_named_property(env, deviceInfo, "manufacturer", manufacturerValue);

        napi_set_element(env, result, j++, deviceInfo);
    }

    delete[] deviceIds;
#endif
#ifdef WIN32
    HRESULT hres = S_OK;
    IMMDeviceEnumerator *pEnumerator = NULL;
    IMMDeviceCollection *pCollection = NULL;
    IMMDevice *pEndpoint = NULL;
    IPropertyStore *pProps = NULL;
    LPWSTR pwszID = NULL;
    UINT count = 0;

#define EXIT_ON_ERROR(hres) \
    if (FAILED(hres))       \
    {                       \
        goto Exit;          \
    }

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    hres = CoCreateInstance(CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, IID_IMMDeviceEnumerator, (void **)&pEnumerator);
    EXIT_ON_ERROR(hres);

    
    hres = pEnumerator->EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE, &pCollection);
    EXIT_ON_ERROR(hres);

    hres = pCollection->GetCount(&count);
    EXIT_ON_ERROR(hres);

    if (count == 0)
    {
        return result;
    }
    // Each loop PKEY the name of an endpoint device.
    for (ULONG i = 0; i < count; i++)
    {
        napi_value device;
        napi_create_object(env, &device);
        // Get pointer to endpoint number i.
        hres = pCollection->Item(i, &pEndpoint);
        EXIT_ON_ERROR(hres);

        // Get the endpoint ID string.
        hres = pEndpoint->GetId(&pwszID);
        EXIT_ON_ERROR(hres);

        char *str = ConvertLPWSTRToChar(pwszID);
        napi_value propName;
        napi_value propValue;
        napi_create_string_utf8(env, "PKEY_Device_InstanceId", NAPI_AUTO_LENGTH, &propName);
        napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
        napi_set_property(env, device, propName, propValue);

        hres = pEndpoint->OpenPropertyStore(STGM_READ, &pProps);
        EXIT_ON_ERROR(hres);

        PROPVARIANT varName;
        // Initialize container for property value.
        PropVariantInit(&varName);

        // Get the endpoint's friendly-name property.
        hres = pProps->GetValue(PKEY_DeviceInterface_FriendlyName, &varName);
        EXIT_ON_ERROR(hres);

        // GetValue succeeds and returns S_OK if PKEY_DeviceInterface_FriendlyName is not found.
        // In this case vartName.vt is set to VT_EMPTY.
        if (varName.vt != VT_EMPTY)
        {
            char *str = ConvertLPWSTRToChar(varName.pwszVal);

            napi_value propName;
            napi_value propValue;
            napi_create_string_utf8(env, "PKEY_DeviceInterface_FriendlyName", NAPI_AUTO_LENGTH, &propName);
            napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
            napi_set_property(env, device, propName, propValue);
        };

        // Get the endpoint's friendly-name property.
        hres = pProps->GetValue(PKEY_Device_DeviceDesc, &varName);
        EXIT_ON_ERROR(hres);

        // GetValue succeeds and returns S_OK if PKEY_Device_DeviceDesc is not found.
        // In this case vartName.vt is set to VT_EMPTY.
        if (varName.vt != VT_EMPTY)
        {
            char *str = ConvertLPWSTRToChar(varName.pwszVal);

            napi_value propName;
            napi_value propValue;
            napi_create_string_utf8(env, "PKEY_Device_DeviceDesc", NAPI_AUTO_LENGTH, &propName);
            napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
            napi_set_property(env, device, propName, propValue);
        };

        // Get the endpoint's friendly-name property.
        hres = pProps->GetValue(PKEY_Device_FriendlyName, &varName);
        EXIT_ON_ERROR(hres);

        // GetValue succeeds and returns S_OK if PKEY_Device_FriendlyName is not found.
        // In this case vartName.vt is set to VT_EMPTY.
        if (varName.vt != VT_EMPTY)
        {
            char *str = ConvertLPWSTRToChar(varName.pwszVal);

            napi_value propName;
            napi_value propValue;
            napi_create_string_utf8(env, "PKEY_Device_FriendlyName", NAPI_AUTO_LENGTH, &propName);
            napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &propValue);
            napi_set_property(env, device, propName, propValue);
        };

        napi_set_element(env, result, i, device);

        CoTaskMemFree(pwszID);
        pwszID = NULL;
        PropVariantClear(&varName);
        SAFE_RELEASE(pEndpoint);
        SAFE_RELEASE(pProps);
    }

Exit:
    CoTaskMemFree(pwszID);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pCollection);
    SAFE_RELEASE(pEndpoint);
    SAFE_RELEASE(pProps);
    CoUninitialize();
#endif
    return result;
}

napi_value GetGraphic(napi_env env, napi_callback_info info)
{
    napi_value result;
    std::string graphic = "";

#ifdef __APPLE__
    std::string command = "system_profiler SPDisplaysDataType";
    std::string output = executeCommand(command);
    graphic = extractChipsetModel(output);
#endif
#ifdef WIN32
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    HRESULT hres = S_OK;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }



    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Use the IWbemServices pointer to make requests of WMI
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Caption FROM Win32_DisplayControllerConfiguration"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;

    // Get the data from the query result
    hres = pEnumerator->Next(
        WBEM_INFINITE,
        1,
        &pclsObj,
        &uReturn);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    VARIANT vtProp;

    // Get the value of the Caption property
    hres = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);

    if (FAILED(hres))
    {
        SAFE_RELEASE(pclsObj);
        SAFE_RELEASE(pEnumerator);
        SAFE_RELEASE(pSvc);
        SAFE_RELEASE(pLoc);
        const char *errorMessage = GetErrorMessageFromHRESULT(hres);
        napi_throw_error(env, NULL, errorMessage);
        CoUninitialize();
        LocalFree((HLOCAL)errorMessage);
        return NULL;
    }

    // Convert the Caption value to a string
    std::wstring caption_buf = vtProp.bstrVal;
    int size = WideCharToMultiByte(CP_UTF8, 0, caption_buf.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string captionStr(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, caption_buf.c_str(), -1, &captionStr[0], size, nullptr, nullptr);

    graphic = captionStr;

    // Clean up
    VariantClear(&vtProp);
    SAFE_RELEASE(pclsObj);
    SAFE_RELEASE(pEnumerator);
    SAFE_RELEASE(pSvc);
    SAFE_RELEASE(pLoc);
    CoUninitialize();
#endif

    napi_create_string_utf8(env, graphic.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value GetDiskSpaceInfo(napi_env env, napi_callback_info info) {
    napi_status status;
    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (status != napi_ok || argc < 1) {
        napi_throw_error(env, NULL, "Invalid argument");
        return NULL;
    }

    // Get drive name
    size_t driveNameLength;
    status = napi_get_value_string_utf8(env, args[0], NULL, 0, &driveNameLength);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid drive name");
        return NULL;
    }

    char* driveName = (char*)malloc(driveNameLength + 1);
    if (driveName == NULL) {
        napi_throw_error(env, NULL, "Memory allocation failed");
        return NULL;
    }

    status = napi_get_value_string_utf8(env, args[0], driveName, driveNameLength + 1, NULL);
    if (status != napi_ok) {
        free(driveName);
        napi_throw_error(env, NULL, "Invalid drive name");
        return NULL;
    }

    // Get disk space information
    uint64_t totalSpace = 0;
    uint64_t availableSpace = 0;

#ifdef _WIN32
    ULARGE_INTEGER totalBytes;
    ULARGE_INTEGER availableBytes;
    ULARGE_INTEGER freeBytes;
    if (GetDiskFreeSpaceExA(driveName, &availableBytes, &totalBytes, &freeBytes)) {
        totalSpace = totalBytes.QuadPart;
        availableSpace = availableBytes.QuadPart;
    } else {
        free(driveName);
        napi_throw_error(env, NULL, "Failed to get disk space");
        return NULL;
    }
#endif

#ifdef __APPLE__
    struct statfs buf;
    if (statfs(driveName, &buf) == 0) {
        unsigned long block_size = buf.f_bsize;
        unsigned long total_blocks = buf.f_blocks;
        unsigned long available_blocks = buf.f_bavail;

        totalSpace = total_blocks * block_size;
        availableSpace = available_blocks * block_size;
    } else {
        free(driveName);
        napi_throw_error(env, NULL, "Failed to get disk space");
        return NULL;
    }
#endif

    free(driveName);

    // Create result object
    napi_value result;
    status = napi_create_object(env, &result);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create result object");
        return NULL;
    }

    // Set properties on the result object
    napi_value totalSpaceValue;
    napi_value availableSpaceValue;
    status = napi_create_int64(env, totalSpace, &totalSpaceValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create total space value");
        return NULL;
    }
    status = napi_create_int64(env, availableSpace, &availableSpaceValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create free space value");
        return NULL;
    }
    status = napi_set_named_property(env, result, "total", totalSpaceValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to set total property");
        return NULL;
    }
    status = napi_set_named_property(env, result, "available", availableSpaceValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to set available property");
        return NULL;
    }

    return result;
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        {"getUUID", 0, GetDeviceUUID, 0, 0, 0, napi_default, 0},
        {"getSerialNumber", 0, GetSerialNumber, 0, 0, 0, napi_default, 0},
        {"getSystemVersion", 0, GetSystemVersion, 0, 0, 0, napi_default, 0},
        {"getSystemArch", 0, GetSystemArch, 0, 0, 0, napi_default, 0},
        {"getProductName", 0, GetProductName, 0, 0, 0, napi_default, 0},
        {"getMemorySize", 0, GetMemorySize, 0, 0, 0, napi_default, 0},
        {"getCPU", 0, GetCPU, 0, 0, 0, napi_default, 0},
        {"getScreenInfo", 0, GetScreenInfo, 0, 0, 0, napi_default, 0},
        {"getVendor", 0, GetVendor, 0, 0, 0, napi_default, 0},
        {"getCaption", 0, GetCaption, 0, 0, 0, napi_default, 0},
        {"getAudioDevices", 0, GetAudioDevices, 0, 0, 0, napi_default, 0},
        {"getVideoDevices", 0, GetVideoDevices, 0, 0, 0, napi_default, 0},
        {"getMicrophoneDevices", 0, GetMicrophoneDevices, 0, 0, 0, napi_default, 0},
        {"getSpeakerDevices", 0, GetSpeakerDevices, 0, 0, 0, napi_default, 0},
        {"getGraphic", 0, GetGraphic, 0, 0, 0, napi_default, 0},
        {"getDiskSpaceInfo", 0, GetDiskSpaceInfo, 0, 0, 0, napi_default, 0}
    };


    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(*descriptors), descriptors);
    return exports;
}

NAPI_MODULE(addon, Init)
