#include "ConfigManager.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <winreg.h>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")

namespace ConfigManager {

std::wstring GetDriversIniPath() {
    WCHAR systemRoot[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        GetWindowsDirectoryW(systemRoot, MAX_PATH);
    }
    return std::wstring(systemRoot) + L"\\drivers.ini";
}

std::wstring GetDriverPath() {
    WCHAR systemRoot[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        GetWindowsDirectoryW(systemRoot, MAX_PATH);
    }
    return std::wstring(systemRoot) + L"\\System32\\drivers\\RTCore64.sys";
}

bool UpdateDriversIni(uint64_t seCiCallbacks, uint64_t safeFunction) {
    std::wstring filePath = GetDriversIniPath();
    
    if (GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[*] drivers.ini not found - skipping file update\n";
        return false;
    }
    
    std::wcout << L"[*] Updating drivers.ini with current offsets...\n";
    
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open drivers.ini for reading\n";
        return false;
    }
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }
    
    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead = 0;
    
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr)) {
        CloseHandle(hFile);
        std::wcout << L"[-] Failed to read drivers.ini\n";
        return false;
    }
    
    CloseHandle(hFile);
    
    // Convert bytes to wstring (skip BOM if present)
    std::wstring content;
    if (fileSize >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE) {
        content = std::wstring((wchar_t*)(buffer.data() + 2), (fileSize - 2) / sizeof(wchar_t));
    }
    else {
        content = std::wstring((wchar_t*)buffer.data(), fileSize / sizeof(wchar_t));
    }

    // Find [Config] section
    size_t configPos = content.find(L"[Config]");
    if (configPos == std::wstring::npos) {
        std::wcout << L"[-] [Config] section not found\n";
        return false;
    }

    // Find next section boundary (or end of file)
    size_t nextSection = content.find(L"\n[", configPos + 1);
    size_t sectionEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();

    // Find IoControlCode_Write line as our anchor point within [Config]
    size_t anchorPos = content.find(L"IoControlCode_Write=", configPos);
    if (anchorPos == std::wstring::npos || anchorPos >= sectionEnd) {
        std::wcout << L"[-] IoControlCode_Write not found in [Config] section\n";
        return false;
    }

    // Find the end of the anchor line
    size_t anchorLineEnd = content.find(L'\n', anchorPos);
    if (anchorLineEnd == std::wstring::npos || anchorLineEnd > sectionEnd) {
        anchorLineEnd = sectionEnd;
    }

    // Prepare expected values with comments
    std::wstringstream expectedSeCi;
    expectedSeCi << L"Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << seCiCallbacks 
                 << L"     ; g_CiCallbacks structure base (static offset in ntoskrnl)";

    std::wstringstream expectedSafe;
    expectedSafe << L"Offset_SafeFunction=0x" << std::hex << std::uppercase << safeFunction
                 << L"      ; ZwFlushInstructionCache - always-success dummy function";

    // Check if current values are already correct
    bool seCiNeedsUpdate = true;
    bool safeNeedsUpdate = true;

    size_t seCiPos = content.find(L"Offset_SeCiCallbacks=", configPos);
    if (seCiPos != std::wstring::npos && seCiPos < sectionEnd) {
        size_t lineEnd = content.find(L'\n', seCiPos);
        if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
        std::wstring currentLine = content.substr(seCiPos, lineEnd - seCiPos);
        if (currentLine == expectedSeCi.str()) {
            seCiNeedsUpdate = false;
        }
    }

    size_t safePos = content.find(L"Offset_SafeFunction=", configPos);
    if (safePos != std::wstring::npos && safePos < sectionEnd) {
        size_t lineEnd = content.find(L'\n', safePos);
        if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
        std::wstring currentLine = content.substr(safePos, lineEnd - safePos);
        if (currentLine == expectedSafe.str()) {
            safeNeedsUpdate = false;
        }
    }

    // If both values are already correct, skip writing
    if (!seCiNeedsUpdate && !safeNeedsUpdate) {
        std::wcout << L"[+] drivers.ini already has correct offsets - no update needed\n";
        return true;
    }

    // Perform updates
    if (seCiNeedsUpdate) {
        // Re-find position after any previous modifications
        seCiPos = content.find(L"Offset_SeCiCallbacks=", configPos);
        
        if (seCiPos != std::wstring::npos && seCiPos < sectionEnd) {
            // Update existing line
            size_t lineEnd = content.find(L'\n', seCiPos);
            if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
            
            content.replace(seCiPos, lineEnd - seCiPos, expectedSeCi.str());
            
            // Recalculate section end after replacement
            nextSection = content.find(L"\n[", configPos + 1);
            sectionEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();
        } else {
            // Add new line after IoControlCode_Write
            std::wstring newLine = L"\n" + expectedSeCi.str();
            content.insert(anchorLineEnd, newLine);
            
            // Recalculate section end after insertion
            nextSection = content.find(L"\n[", configPos + 1);
            sectionEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();
        }
    }

    if (safeNeedsUpdate) {
        // Re-find position after any previous modifications
        safePos = content.find(L"Offset_SafeFunction=", configPos);
        
        if (safePos != std::wstring::npos && safePos < sectionEnd) {
            // Update existing line
            size_t lineEnd = content.find(L'\n', safePos);
            if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
            
            content.replace(safePos, lineEnd - safePos, expectedSafe.str());
        } else {
            // Add new line after IoControlCode_Write (recalculate anchor position)
            anchorPos = content.find(L"IoControlCode_Write=", configPos);
            anchorLineEnd = content.find(L'\n', anchorPos);
            if (anchorLineEnd == std::wstring::npos) {
                nextSection = content.find(L"\n[", configPos + 1);
                anchorLineEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();
            }
            
            std::wstring newLine = L"\n" + expectedSafe.str();
            content.insert(anchorLineEnd, newLine);
        }
    }

    // Write back with UTF-16 LE BOM
    hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open drivers.ini for writing (run as Administrator)\n";
        return false;
    }
    
    BYTE bom[2] = { 0xFF, 0xFE };
    DWORD bytesWritten = 0;
    WriteFile(hFile, bom, 2, &bytesWritten, nullptr);
    
    DWORD contentSize = (DWORD)(content.length() * sizeof(wchar_t));
    if (!WriteFile(hFile, content.c_str(), contentSize, &bytesWritten, nullptr)) {
        CloseHandle(hFile);
        std::wcout << L"[-] Failed to write to drivers.ini\n";
        return false;
    }
    
    CloseHandle(hFile);
    
    std::wcout << L"[+] Updated drivers.ini:\n";
    std::wcout << L"    Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << seCiCallbacks << L"\n";
    std::wcout << L"    Offset_SafeFunction=0x" << std::uppercase << safeFunction << std::dec << L"\n";
    
    return true;
}

bool SaveOffsetsToRegistry(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& buildInfo) {
    HKEY hKey;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestamp[32];
    swprintf_s(timestamp, L"%04d%02d%02d_%02d%02d%02d", 
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    std::wstring historyPath = L"Software\\drvloader\\History\\";
    historyPath += timestamp;
    
    LSTATUS result = RegCreateKeyExW(HKEY_CURRENT_USER, historyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    
    if (result != ERROR_SUCCESS) {
        std::wcout << L"[-] Failed to create registry key (error: " << result << L")\n";
        return false;
    }
    
    wchar_t timestampStr[64];
    swprintf_s(timestampStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    RegSetValueExW(hKey, L"Timestamp", 0, REG_SZ, (BYTE*)timestampStr, 
        (DWORD)((wcslen(timestampStr) + 1) * sizeof(wchar_t)));
    
    DWORD seCiDword = (DWORD)seCiCallbacks;
    RegSetValueExW(hKey, L"SeCiCallbacks", 0, REG_DWORD, (BYTE*)&seCiDword, sizeof(DWORD));
    
    DWORD safeDword = (DWORD)safeFunction;
    RegSetValueExW(hKey, L"SafeFunction", 0, REG_DWORD, (BYTE*)&safeDword, sizeof(DWORD));
    
    RegSetValueExW(hKey, L"BuildInfo", 0, REG_SZ, (BYTE*)buildInfo.c_str(),
        (DWORD)((buildInfo.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    std::wcout << L"[+] Saved offsets to registry: HKCU\\Software\\drvloader\\History\\" << timestamp << L"\n";
    
    // Keep only the last 8 history entries
    HKEY hHistoryKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\History", 0, 
        KEY_READ | KEY_WRITE, &hHistoryKey) == ERROR_SUCCESS) {
        
        std::vector<std::wstring> entries;
        wchar_t subKeyName[256];
        DWORD index = 0;
        
        while (RegEnumKeyW(hHistoryKey, index++, subKeyName, 256) == ERROR_SUCCESS) {
            entries.push_back(subKeyName);
        }
        
        if (entries.size() > 8) {
            std::sort(entries.begin(), entries.end());
            for (size_t i = 0; i < entries.size() - 8; i++) {
                RegDeleteTreeW(hHistoryKey, entries[i].c_str());
            }
        }
        
        RegCloseKey(hHistoryKey);
    }
    
    return true;
}

bool SaveOriginalCallbacksToRegistry(const std::vector<uint64_t>& callbacks) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    
    DWORD count = (DWORD)callbacks.size();
    RegSetValueExW(hKey, L"CallbackCount", 0, REG_DWORD, (BYTE*)&count, sizeof(DWORD));
    
    for (DWORD i = 0; i < count; i++) {
        wchar_t name[32];
        swprintf_s(name, L"OriginalCallback%d", i);
        RegSetValueExW(hKey, name, 0, REG_QWORD, (BYTE*)&callbacks[i], sizeof(uint64_t));
    }
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestampStr[64];
    swprintf_s(timestampStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    RegSetValueExW(hKey, L"PatchTimestamp", 0, REG_SZ, (BYTE*)timestampStr,
        (DWORD)((wcslen(timestampStr) + 1) * sizeof(wchar_t)));
    
    DWORD isPatched = 1;
    RegSetValueExW(hKey, L"IsPatched", 0, REG_DWORD, (BYTE*)&isPatched, sizeof(DWORD));
    
    RegCloseKey(hKey);
    return true;
}

std::vector<uint64_t> LoadOriginalCallbacksFromRegistry() {
    std::vector<uint64_t> callbacks;
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0, 
        KEY_READ, &hKey) != ERROR_SUCCESS) {
        return callbacks;
    }
    
    DWORD count = 0;
    DWORD dataSize = sizeof(DWORD);
    if (RegQueryValueExW(hKey, L"CallbackCount", nullptr, nullptr, (BYTE*)&count, &dataSize) != ERROR_SUCCESS) {
        // Fallback for single value
        uint64_t single = 0;
        dataSize = sizeof(uint64_t);
        if (RegQueryValueExW(hKey, L"OriginalCallback", nullptr, nullptr, (BYTE*)&single, &dataSize) == ERROR_SUCCESS) {
            callbacks.push_back(single);
        }
        RegCloseKey(hKey);
        return callbacks;
    }
    
    for (DWORD i = 0; i < count; i++) {
        wchar_t name[32];
        swprintf_s(name, L"OriginalCallback%d", i);
        uint64_t val = 0;
        dataSize = sizeof(uint64_t);
        if (RegQueryValueExW(hKey, name, nullptr, nullptr, (BYTE*)&val, &dataSize) == ERROR_SUCCESS) {
            callbacks.push_back(val);
        }
    }
    
    RegCloseKey(hKey);
    return callbacks;
}

bool ClearPatchStateFromRegistry() {
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0,
        KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    RegDeleteValueW(hKey, L"OriginalCallback");
    RegDeleteValueW(hKey, L"PatchTimestamp");
    
    DWORD isPatched = 0;
    RegSetValueExW(hKey, L"IsPatched", 0, REG_DWORD, (BYTE*)&isPatched, sizeof(DWORD));
    
    RegCloseKey(hKey);
    
    std::wcout << L"[+] Cleared patch state from registry\n";
    return true;
}

bool CheckAndDisableMemoryIntegrity() {
    HKEY hKey;
    LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ | KEY_WRITE, &hKey);
    
    if (result != ERROR_SUCCESS) {
        return true;
    }
    
    DWORD enabled = 0;
    DWORD dataSize = sizeof(DWORD);
    result = RegQueryValueExW(hKey, L"Enabled", nullptr, nullptr, (LPBYTE)&enabled, &dataSize);
    
    if (result == ERROR_SUCCESS && enabled == 1) {
        std::wcout << L"[!] WARNING: Memory Integrity (Hypervisor Enforced Code Integrity) is enabled!\n";
        std::wcout << L"[!] DSE patching will succeed, but loading unsigned drivers will cause BSOD.\n";
        std::wcout << L"[!] Do you want to disable Memory Integrity and reboot? (Y/N): ";
        
        wchar_t choice;
        std::wcin >> choice;
        std::wcin.clear();
        std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
        
        if (choice == L'Y' || choice == L'y') {
            enabled = 0;
            RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD, (const BYTE*)&enabled, sizeof(enabled));
            RegDeleteValueW(hKey, L"WasEnabledBy");
            
            std::wcout << L"[+] Memory Integrity disabled. System will reboot to apply changes.\n";
            std::wcout << L"[+] Press any key to continue with reboot...";
            std::wcout.flush();
            FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
            _getwch();
            std::wcout << L"\n";
            
            HANDLE hToken;
            TOKEN_PRIVILEGES tkp;
            
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                
                AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, 0);
                CloseHandle(hToken);
            }
            
            WCHAR rebootMsg[] = L"Memory Integrity disabled for DSE bypass";
            InitiateSystemShutdownExW(nullptr, rebootMsg, 0, TRUE, TRUE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
            ExitProcess(0);
        } else {
            std::wcout << L"[!] Memory Integrity remains enabled. DSE bypass may cause BSOD on driver load.\n";
            std::wcout << L"[!] Continuing at your own risk...\n\n";
        }
    }
    
    RegCloseKey(hKey);
    return true;
}

// ============================================================================
// IN-MEMORY PDB PROCESSING - No temporary files!
// ============================================================================

// Mini-PDB structure (96 bytes)
#pragma pack(push, 1)
struct MiniPdb {
    char Magic[8];              // "MINIPDB\0"
    uint32_t Version;           // 1
    uint32_t Reserved;
    uint64_t SeCiCallbacks;
    uint64_t ZwFlushInstructionCache;
};
#pragma pack(pop)

std::wstring GetWindowsBuildNumber() {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    DWORD verHandle = 0;
    DWORD verSize = GetFileVersionInfoSizeW(ntoskrnlPath.c_str(), &verHandle);
    if (verSize == 0) return L"Unknown";
    
    std::vector<BYTE> verData(verSize);
    if (!GetFileVersionInfoW(ntoskrnlPath.c_str(), 0, verSize, verData.data())) {
        return L"Unknown";
    }
    
    VS_FIXEDFILEINFO* pFileInfo = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(verData.data(), L"\\", (LPVOID*)&pFileInfo, &len)) {
        return L"Unknown";
    }
    
    wchar_t buildNumber[64];
    swprintf_s(buildNumber, L"%d.%d.%d.%d",
        HIWORD(pFileInfo->dwFileVersionMS),
        LOWORD(pFileInfo->dwFileVersionMS),
        HIWORD(pFileInfo->dwFileVersionLS),
        LOWORD(pFileInfo->dwFileVersionLS));
    
    return buildNumber;
}

bool CreateMiniPdb(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& outputPath) {
    std::wcout << L"[*] Creating mini-PDB file...\n";
    
    MiniPdb mpdb = {};
    memcpy(mpdb.Magic, "MINIPDB", 8);
    mpdb.Version = 1;
    mpdb.SeCiCallbacks = seCiCallbacks;
    mpdb.ZwFlushInstructionCache = safeFunction;
    
    // Create directory if needed
    size_t lastSlash = outputPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        std::wstring dirPath = outputPath.substr(0, lastSlash);
        SHCreateDirectoryExW(nullptr, dirPath.c_str(), nullptr);
    }
    
    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr, 
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to create mini-PDB file\n";
        return false;
    }
    
    DWORD written;
    bool success = WriteFile(hFile, &mpdb, sizeof(mpdb), &written, nullptr);
    CloseHandle(hFile);
    
    if (!success || written != sizeof(mpdb)) {
        std::wcout << L"[-] Failed to write mini-PDB data\n";
        return false;
    }
    
    std::wcout << L"[+] Mini-PDB created: " << outputPath << L" (" << sizeof(mpdb) << L" bytes)\n";
    return true;
}

bool LoadOffsetsFromMiniPdb(const std::wstring& mpdbPath, uint64_t* outSeCi, uint64_t* outSafe) {
    HANDLE hFile = CreateFileW(mpdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    MiniPdb mpdb;
    DWORD read;
    bool success = ReadFile(hFile, &mpdb, sizeof(mpdb), &read, nullptr);
    CloseHandle(hFile);
    
    if (!success || read != sizeof(mpdb)) {
        return false;
    }
    
    // Verify magic and version
    if (memcmp(mpdb.Magic, "MINIPDB", 8) != 0 || mpdb.Version != 1) {
        std::wcout << L"[-] Invalid mini-PDB format\n";
        return false;
    }
    
    *outSeCi = mpdb.SeCiCallbacks;
    *outSafe = mpdb.ZwFlushInstructionCache;
    
    std::wcout << L"[+] Loaded offsets from mini-PDB:\n";
    std::wcout << L"    SeCiCallbacks: 0x" << std::hex << *outSeCi << std::dec << L"\n";
    std::wcout << L"    SafeFunction: 0x" << std::hex << *outSafe << std::dec << L"\n";
    
    return true;
}

bool CreateWindowsMiniPdb(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& pdbGuid) {
    std::wstring buildNumber = GetWindowsBuildNumber();
    
    // Prepare mini-PDB structure
    MiniPdb mpdb = {};
    memcpy(mpdb.Magic, "MINIPDB", 8);
    mpdb.Version = 1;
    mpdb.SeCiCallbacks = seCiCallbacks;
    mpdb.ZwFlushInstructionCache = safeFunction;
    
    std::wcout << L"[*] Creating Windows mini-PDB for build " << buildNumber << L"...\n";
    
    // Primary location: %SystemRoot%\symbols\ntkrnlmp.pdb\{GUID}\ntkrnlmp.mpdb
    // This works on any drive letter (C:, D:, etc.)
    WCHAR sysRoot[MAX_PATH];
    if (GetWindowsDirectoryW(sysRoot, MAX_PATH) > 0) {
        std::wstring mpdbPath = std::wstring(sysRoot) + L"\\symbols\\ntkrnlmp.pdb\\" + pdbGuid + L"\\ntkrnlmp.mpdb";
        std::wstring dirPath = std::wstring(sysRoot) + L"\\symbols\\ntkrnlmp.pdb\\" + pdbGuid;
        
        SHCreateDirectoryExW(nullptr, dirPath.c_str(), nullptr);
        
        HANDLE hFile = CreateFileW(mpdbPath.c_str(), GENERIC_WRITE, 0, nullptr, 
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            bool success = WriteFile(hFile, &mpdb, sizeof(mpdb), &written, nullptr);
            CloseHandle(hFile);
            
            if (success && written == sizeof(mpdb)) {
                std::wcout << L"[+] Mini-PDB created: " << mpdbPath << L" (" << sizeof(mpdb) << L" bytes)\n";
                std::wcout << L"    Build: " << buildNumber << L"\n";
                std::wcout << L"    SeCiCallbacks: 0x" << std::hex << seCiCallbacks << std::dec << L"\n";
                std::wcout << L"    SafeFunction: 0x" << std::hex << safeFunction << std::dec << L"\n";
                return true;
            }
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED) {
                std::wcout << L"[-] Access denied to " << mpdbPath << L"\n";
            }
        }
    }
    
    // Fallback: ProgramData (always accessible, even without admin)
    std::wcout << L"[*] Trying fallback: ProgramData\\dbg\\sym\\...\n";
    
    WCHAR progData[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, progData) == S_OK) {
        std::wstring mpdbPath = std::wstring(progData) + L"\\dbg\\sym\\ntkrnlmp.pdb\\" + pdbGuid + L"\\ntkrnlmp.mpdb";
        std::wstring dirPath = std::wstring(progData) + L"\\dbg\\sym\\ntkrnlmp.pdb\\" + pdbGuid;
        
        SHCreateDirectoryExW(nullptr, dirPath.c_str(), nullptr);
        
        HANDLE hFile = CreateFileW(mpdbPath.c_str(), GENERIC_WRITE, 0, nullptr, 
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::wcout << L"[-] Failed to create mini-PDB (error: " << GetLastError() << L")\n";
            return false;
        }
        
        DWORD written;
        bool success = WriteFile(hFile, &mpdb, sizeof(mpdb), &written, nullptr);
        CloseHandle(hFile);
        
        if (!success || written != sizeof(mpdb)) {
            std::wcout << L"[-] Failed to write mini-PDB data\n";
            return false;
        }
        
        std::wcout << L"[+] Mini-PDB created: " << mpdbPath << L" (" << sizeof(mpdb) << L" bytes)\n";
        std::wcout << L"    Build: " << buildNumber << L"\n";
        std::wcout << L"    SeCiCallbacks: 0x" << std::hex << seCiCallbacks << std::dec << L"\n";
        std::wcout << L"    SafeFunction: 0x" << std::hex << safeFunction << std::dec << L"\n";
        
        return true;
    }
    
    std::wcout << L"[-] All mini-PDB creation attempts failed\n";
    return false;
}

bool LoadOffsetsFromWindowsMiniPdb(uint64_t* outSeCi, uint64_t* outSafe, const std::wstring& pdbGuid) {
    WCHAR progData[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, progData);
    
    std::wstring mpdbPath = std::wstring(progData) + L"\\dbg\\sym\\ntkrnlmp.pdb\\" + pdbGuid + L"\\ntkrnlmp.mpdb";

    HANDLE hFile = CreateFileW(mpdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                              nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        WCHAR winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        
        mpdbPath = std::wstring(winDir) + L"\\symbols\\ntkrnlmp.pdb\\" + pdbGuid + L"\\ntkrnlmp.mpdb";
        hFile = CreateFileW(mpdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                           nullptr, OPEN_EXISTING, 0, nullptr);
        
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
    }

    MiniPdb mpdb;
    DWORD read;
    bool success = ReadFile(hFile, &mpdb, sizeof(mpdb), &read, nullptr);
    CloseHandle(hFile);

    if (!success || read != sizeof(mpdb)) {
        return false;
    }

    if (memcmp(mpdb.Magic, "MINIPDB", 8) != 0 || mpdb.Version != 1) {
        return false;
    }

    *outSeCi = mpdb.SeCiCallbacks;
    *outSafe = mpdb.ZwFlushInstructionCache;

    std::wcout << L"[+] Loaded offsets from mini-PDB: " << mpdbPath << L"\n";
    std::wcout << L"    SeCiCallbacks: 0x" << std::hex << *outSeCi << std::dec << L"\n";
    std::wcout << L"    SafeFunction: 0x" << std::hex << *outSafe << std::dec << L"\n";

    return true;
}

// ============================================================================
// DRIVER LOAD HISTORY MANAGEMENT
// ============================================================================

bool SaveDriverLoadHistory(const std::wstring& driverPath, const std::wstring& serviceName,
                           DWORD startType, bool success) {
    HKEY hKey;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestampRaw[32];
    swprintf_s(timestampRaw, L"%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    std::wstring historyPath = L"Software\\drvloader\\LoadedDrivers\\History\\";
    historyPath += timestampRaw;
    
    LSTATUS result = RegCreateKeyExW(HKEY_CURRENT_USER, historyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    
    if (result != ERROR_SUCCESS) {
        std::wcout << L"[-] Failed to create driver history registry key (error: " << result << L")\n";
        return false;
    }
    
    wchar_t timestampStr[64];
    swprintf_s(timestampStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    RegSetValueExW(hKey, L"Timestamp", 0, REG_SZ, (BYTE*)timestampStr,
        (DWORD)((wcslen(timestampStr) + 1) * sizeof(wchar_t)));
    
    RegSetValueExW(hKey, L"DriverPath", 0, REG_SZ, (BYTE*)driverPath.c_str(),
        (DWORD)((driverPath.length() + 1) * sizeof(wchar_t)));
    
    RegSetValueExW(hKey, L"ServiceName", 0, REG_SZ, (BYTE*)serviceName.c_str(),
        (DWORD)((serviceName.length() + 1) * sizeof(wchar_t)));
    
    RegSetValueExW(hKey, L"StartType", 0, REG_DWORD, (BYTE*)&startType, sizeof(DWORD));
    
    DWORD successFlag = success ? 1 : 0;
    RegSetValueExW(hKey, L"LoadResult", 0, REG_DWORD, (BYTE*)&successFlag, sizeof(DWORD));
    
    RegCloseKey(hKey);
    
    std::wcout << L"[+] Saved driver load to history: " << serviceName << L"\n";
    
    // Keep only the last 8 history entries
    HKEY hHistoryKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LoadedDrivers\\History", 0,
        KEY_READ | KEY_WRITE, &hHistoryKey) == ERROR_SUCCESS) {
        
        std::vector<std::wstring> entries;
        wchar_t subKeyName[256];
        DWORD index = 0;
        
        while (RegEnumKeyW(hHistoryKey, index++, subKeyName, 256) == ERROR_SUCCESS) {
            entries.push_back(subKeyName);
        }
        
        if (entries.size() > 8) {
            std::sort(entries.begin(), entries.end());
            for (size_t i = 0; i < entries.size() - 8; i++) {
                RegDeleteTreeW(hHistoryKey, entries[i].c_str());
            }
        }
        
        RegCloseKey(hHistoryKey);
    }
    
    return true;
}

std::vector<DriverHistoryEntry> GetDriverLoadHistory() {
    std::vector<DriverHistoryEntry> history;
    
    HKEY hHistoryKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LoadedDrivers\\History", 0,
        KEY_READ, &hHistoryKey) != ERROR_SUCCESS) {
        return history;
    }
    
    wchar_t subKeyName[256];
    DWORD index = 0;
    
    while (RegEnumKeyW(hHistoryKey, index++, subKeyName, 256) == ERROR_SUCCESS) {
        HKEY hEntryKey;
        std::wstring entryPath = L"Software\\drvloader\\LoadedDrivers\\History\\";
        entryPath += subKeyName;
        
        if (RegOpenKeyExW(HKEY_CURRENT_USER, entryPath.c_str(), 0, KEY_READ, &hEntryKey) == ERROR_SUCCESS) {
            DriverHistoryEntry entry;
            entry.timestampRaw = subKeyName;
            
            wchar_t buffer[MAX_PATH];
            DWORD bufferSize = sizeof(buffer);
            
            if (RegQueryValueExW(hEntryKey, L"Timestamp", nullptr, nullptr, (BYTE*)buffer, &bufferSize) == ERROR_SUCCESS) {
                entry.timestamp = buffer;
            }
            
            bufferSize = sizeof(buffer);
            if (RegQueryValueExW(hEntryKey, L"DriverPath", nullptr, nullptr, (BYTE*)buffer, &bufferSize) == ERROR_SUCCESS) {
                entry.driverPath = buffer;
            }
            
            bufferSize = sizeof(buffer);
            if (RegQueryValueExW(hEntryKey, L"ServiceName", nullptr, nullptr, (BYTE*)buffer, &bufferSize) == ERROR_SUCCESS) {
                entry.serviceName = buffer;
            }
            
            DWORD startType = 0;
            bufferSize = sizeof(DWORD);
            if (RegQueryValueExW(hEntryKey, L"StartType", nullptr, nullptr, (BYTE*)&startType, &bufferSize) == ERROR_SUCCESS) {
                entry.startType = startType;
            }
            
            DWORD successFlag = 0;
            bufferSize = sizeof(DWORD);
            if (RegQueryValueExW(hEntryKey, L"LoadResult", nullptr, nullptr, (BYTE*)&successFlag, &bufferSize) == ERROR_SUCCESS) {
                entry.success = (successFlag == 1);
            }
            
            history.push_back(entry);
            RegCloseKey(hEntryKey);
        }
    }
    
    RegCloseKey(hHistoryKey);
    
    // Sort by timestamp (newest first)
    std::sort(history.begin(), history.end(),
        [](const DriverHistoryEntry& a, const DriverHistoryEntry& b) {
            return a.timestampRaw > b.timestampRaw;
        });
    
    return history;
}

bool ClearDriverLoadHistory() {
    LSTATUS result = RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\drvloader\\LoadedDrivers\\History");
    
    if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
        std::wcout << L"[+] Driver load history cleared\n";
        return true;
    }
    
    std::wcout << L"[-] Failed to clear driver load history (error: " << result << L")\n";
    return false;
}

std::wstring ExtractServiceName(const std::wstring& driverPath) {
    size_t lastSlash = driverPath.find_last_of(L"\\/");
    std::wstring filename = (lastSlash != std::wstring::npos) 
        ? driverPath.substr(lastSlash + 1) 
        : driverPath;
    
    // Remove .sys extension if present
    if (filename.length() >= 4) {
        std::wstring ext = filename.substr(filename.length() - 4);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        if (ext == L".sys") {
            filename = filename.substr(0, filename.length() - 4);
        }
    }
    
    return filename;
}

std::wstring NormalizeDriverPath(const std::wstring& input) {
    // If contains \ or : → treat as full path
    if (input.find(L'\\') != std::wstring::npos || input.find(L':') != std::wstring::npos) {
        // Ensure .sys extension
        std::wstring path = input;
        if (path.length() < 4 || path.substr(path.length() - 4) != L".sys") {
            path += L".sys";
        }
        return path;
    }
    
    // Otherwise → System32\drivers
    std::wstring filename = input;
    
    // Add .sys if missing
    if (filename.length() < 4 || filename.substr(filename.length() - 4) != L".sys") {
        filename += L".sys";
    }
    
    WCHAR sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    return std::wstring(sysDir) + L"\\drivers\\" + filename;
}

} // namespace ConfigManager