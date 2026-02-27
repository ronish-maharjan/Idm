#include <stdio.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

// All 5 known CLSID keys IDM uses
const char* clsidKeys[] = {
    "{6DDF00DB-1234-46EC-8356-27E7B2051192}",
    "{7B8E9164-324D-4A2E-A46D-0165FB2000EC}",
    "{D5B91409-A8CA-4973-9A0B-59F713D25671}",
    "{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}",
    "{07999AC3-058B-40BF-984F-69EB1E554CA7}"
};
int numKeys = 5;

// Fresh trial scansk data (from idm_trial.reg)
BYTE trialScansk[] = {
    0x91,0x1d,0xac,0xd6,0x90,0x5c,0x42,0xea,0xba,0x1a,0xac,0x08,0x1a,0x18,0x2f,0x16,
    0x2a,0xa8,0x0a,0xaa,0x24,0xbf,0x0c,0xfc,0x4e,0x7b,0x3b,0x76,0xf7,0x70,0x93,0x58,
    0x5c,0x03,0x03,0x7e,0x04,0xab,0xb0,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00
};

// ===================== HELPER FUNCTIONS =====================

void printOK(const char* msg) {
    printf("  [+] %s\n", msg);
}
void printFail(const char* msg) {
    printf("  [-] %s (skipping)\n", msg);
}

// ---- FIX 3: Helper to open registry with correct 64bit flag ----
LONG OpenRegKey(HKEY hive, const char* path, REGSAM access, HKEY* outKey) {
    // Try 64-bit view first
    LONG r = RegOpenKeyExA(hive, path, 0, access | KEY_WOW64_64KEY, outKey);
    if (r != ERROR_SUCCESS)
        r = RegOpenKeyExA(hive, path, 0, access, outKey);
    return r;
}

LONG CreateRegKey(HKEY hive, const char* path, HKEY* outKey) {
    LONG r = RegCreateKeyExA(hive, path, 0, NULL, 0,
        KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, outKey, NULL);
    if (r != ERROR_SUCCESS)
        r = RegCreateKeyExA(hive, path, 0, NULL, 0,
            KEY_SET_VALUE, NULL, outKey, NULL);
    return r;
}

// ---- Enable Windows privilege ----
BOOL EnablePrivilege(LPCSTR privilege) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;
    if (!LookupPrivilegeValueA(NULL, privilege, &luid)) {
        CloseHandle(token);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
    return result;
}

// ---- Take ownership of a registry key ----
BOOL TakeOwnership(HKEY hive, const char* subkey) {
    HKEY hKey;
    LONG r = OpenRegKey(hive, subkey, WRITE_OWNER, &hKey);
    if (r != ERROR_SUCCESS) return FALSE;

    PSID adminSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid);

    BOOL res = (SetSecurityInfo(hKey, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
        adminSid, NULL, NULL, NULL) == ERROR_SUCCESS);

    if (adminSid) FreeSid(adminSid);
    RegCloseKey(hKey);
    return res;
}

// ---- Give full access to a registry key ----
BOOL SetFullAccess(HKEY hive, const char* subkey) {
    HKEY hKey;
    LONG r = OpenRegKey(hive, subkey, WRITE_DAC, &hKey);
    if (r != ERROR_SUCCESS) return FALSE;

    PSID everyoneSid = NULL;
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0, &everyoneSid);

    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPSTR)everyoneSid;

    PACL newAcl = NULL;
    SetEntriesInAclA(1, &ea, NULL, &newAcl);

    BOOL res = (SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
        NULL, NULL, newAcl, NULL) == ERROR_SUCCESS);

    if (newAcl) LocalFree(newAcl);
    if (everyoneSid) FreeSid(everyoneSid);
    RegCloseKey(hKey);
    return res;
}

// ---- Set read only on a registry key ----
BOOL SetReadOnly(HKEY hive, const char* subkey) {
    HKEY hKey;
    LONG r = OpenRegKey(hive, subkey, WRITE_DAC, &hKey);
    if (r != ERROR_SUCCESS) return FALSE;

    PSID everyoneSid = NULL;
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0, &everyoneSid);

    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = KEY_READ;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPSTR)everyoneSid;

    PACL newAcl = NULL;
    SetEntriesInAclA(1, &ea, NULL, &newAcl);

    BOOL res = (SetSecurityInfo(hKey, SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, newAcl, NULL) == ERROR_SUCCESS);

    if (newAcl) LocalFree(newAcl);
    if (everyoneSid) FreeSid(everyoneSid);
    RegCloseKey(hKey);
    return res;
}

// ---- Set owner to Nobody (locks the key) ----
BOOL SetOwnerNobody(HKEY hive, const char* subkey) {
    HKEY hKey;
    LONG r = OpenRegKey(hive, subkey, WRITE_OWNER, &hKey);
    if (r != ERROR_SUCCESS) return FALSE;

    PSID nobodySid = NULL;
    SID_IDENTIFIER_AUTHORITY nullAuth = SECURITY_NULL_SID_AUTHORITY;
    AllocateAndInitializeSid(&nullAuth, 1, SECURITY_NULL_RID,
        0, 0, 0, 0, 0, 0, 0, &nobodySid);

    BOOL res = (SetSecurityInfo(hKey, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
        nobodySid, NULL, NULL, NULL) == ERROR_SUCCESS);

    if (nobodySid) FreeSid(nobodySid);
    RegCloseKey(hKey);
    return res;
}

void UnlockKey(HKEY hive, const char* path) {
    TakeOwnership(hive, path);
    SetFullAccess(hive, path);
}

void LockKey(HKEY hive, const char* path) {
    SetReadOnly(hive, path);
    SetOwnerNobody(hive, path);
}

// ---- FIX 2: Delete key AND all subkeys using RegDeleteTree ----
void DeleteKeyFull(HKEY hive, const char* path) {
    // Try with 64bit flag first
    HKEY hKey;
    if (RegOpenKeyExA(hive, path, 0,
        DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        RegDeleteTreeA(hive, path);
    } else {
        RegDeleteTreeA(hive, path);
    }
}

// ---- FIX 1: Search for hidden dynamic CLSID key ----
// Searches HKCR\CLSID for a key containing the marker string
char hiddenKey[256] = "";

void FindHiddenKey() {
    printf("  [*] Searching for hidden dynamic IDM key...\n");

    HKEY hRoot;
    if (RegOpenKeyExA(HKEY_CLASSES_ROOT, "CLSID", 0,
        KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hRoot) != ERROR_SUCCESS) {
        printFail("Could not open HKCR\\CLSID");
        return;
    }

    char subkeyName[256];
    DWORD index = 0;
    DWORD nameSize;

    while (1) {
        nameSize = sizeof(subkeyName);
        LONG r = RegEnumKeyExA(hRoot, index, subkeyName, &nameSize,
            NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) { index++; continue; }

        // Open this subkey and check for marker value
        HKEY hSub;
        char fullPath[512];
        sprintf(fullPath, "CLSID\\%s", subkeyName);

        if (RegOpenKeyExA(HKEY_CLASSES_ROOT, fullPath, 0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hSub) == ERROR_SUCCESS) {

            // Check if it has a value containing our marker
            char valueName[256];
            DWORD valueIndex = 0;
            DWORD valueNameSize;

            while (1) {
                valueNameSize = sizeof(valueName);
                LONG vr = RegEnumValueA(hSub, valueIndex, valueName,
                    &valueNameSize, NULL, NULL, NULL, NULL);
                if (vr == ERROR_NO_MORE_ITEMS) break;

                // Check value name for marker
                if (strstr(valueName, "cDTvBFquXk0") != NULL) {
                    strcpy(hiddenKey, subkeyName);
                    printf("  [+] Found hidden key: %s\n", hiddenKey);
                    RegCloseKey(hSub);
                    RegCloseKey(hRoot);
                    return;
                }
                valueIndex++;
            }

            // Also check the default value data for marker
            BYTE data[512];
            DWORD dataSize = sizeof(data);
            if (RegQueryValueExA(hSub, "", NULL, NULL, data, &dataSize) == ERROR_SUCCESS) {
                data[dataSize] = 0;
                if (strstr((char*)data, "cDTvBFquXk0") != NULL) {
                    strcpy(hiddenKey, subkeyName);
                    printf("  [+] Found hidden key: %s\n", hiddenKey);
                    RegCloseKey(hSub);
                    RegCloseKey(hRoot);
                    return;
                }
            }

            RegCloseKey(hSub);
        }
        index++;
    }

    RegCloseKey(hRoot);
    printf("  [-] Hidden key not found (may not exist on this system)\n");
}

void WriteScanskValue(HKEY hive, const char* subkey) {
    HKEY hKey;
    if (CreateRegKey(hive, subkey, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "scansk", 0, REG_NONE,
            trialScansk, sizeof(trialScansk));
        RegCloseKey(hKey);
    }
}

// ===================== MAIN =====================

int main() {
    int success = 1;
    char path[512];

    printf("==========================================\n");
    printf("         IDM Trial Reset Tool\n");
    printf("==========================================\n\n");

    // --- Check Admin ---
    printf("[*] Checking administrator rights...\n");
    BOOL isAdmin = FALSE;
    PSID adminSid;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid);
    CheckTokenMembership(NULL, adminSid, &isAdmin);
    FreeSid(adminSid);

    if (!isAdmin) {
        printf("  [!] ERROR: Not running as Administrator!\n");
        printf("  [!] Right-click EXE and select Run as administrator\n\n");
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }
    printOK("Running as Administrator");

    // --- Enable Privileges ---
    printf("\n[*] Step 1/7 - Enabling Windows privileges...\n");
    if (EnablePrivilege(SE_TAKE_OWNERSHIP_NAME))
        printOK("SeTakeOwnershipPrivilege enabled");
    else {
        printFail("SeTakeOwnershipPrivilege failed");
        success = 0;
    }
    if (EnablePrivilege(SE_RESTORE_NAME))
        printOK("SeRestorePrivilege enabled");
    else
        printFail("SeRestorePrivilege - not critical");

    // --- FIX 1: Find hidden dynamic key ---
    printf("\n[*] Step 2/7 - Searching for hidden dynamic key...\n");
    FindHiddenKey();

    // --- Unlock All Keys ---
    printf("\n[*] Step 3/7 - Unlocking protected registry keys...\n");
    for (int i = 0; i < numKeys; i++) {
        sprintf(path, "Software\\Classes\\CLSID\\%s", clsidKeys[i]);
        UnlockKey(HKEY_CURRENT_USER, path);
        UnlockKey(HKEY_LOCAL_MACHINE, path);

        sprintf(path, "Software\\Classes\\Wow6432Node\\CLSID\\%s", clsidKeys[i]);
        UnlockKey(HKEY_CURRENT_USER, path);
        UnlockKey(HKEY_LOCAL_MACHINE, path);

        printf("  [+] Unlocked: %s\n", clsidKeys[i]);
    }
    // Unlock hidden key too if found
    if (strlen(hiddenKey) > 0) {
        sprintf(path, "Software\\Classes\\CLSID\\%s", hiddenKey);
        UnlockKey(HKEY_CURRENT_USER, path);
        UnlockKey(HKEY_LOCAL_MACHINE, path);
        sprintf(path, "Software\\Classes\\Wow6432Node\\CLSID\\%s", hiddenKey);
        UnlockKey(HKEY_CURRENT_USER, path);
        UnlockKey(HKEY_LOCAL_MACHINE, path);
        printf("  [+] Unlocked hidden key: %s\n", hiddenKey);
    }

    // --- FIX 2: Delete using RegDeleteTree ---
    printf("\n[*] Step 4/7 - Deleting CLSID keys (including subkeys)...\n");
    for (int i = 0; i < numKeys; i++) {
        sprintf(path, "Software\\Classes\\CLSID\\%s", clsidKeys[i]);
        DeleteKeyFull(HKEY_CURRENT_USER, path);
        DeleteKeyFull(HKEY_LOCAL_MACHINE, path);

        sprintf(path, "Software\\Classes\\Wow6432Node\\CLSID\\%s", clsidKeys[i]);
        DeleteKeyFull(HKEY_CURRENT_USER, path);
        DeleteKeyFull(HKEY_LOCAL_MACHINE, path);

        printf("  [+] Deleted: %s\n", clsidKeys[i]);
    }
    // Delete hidden key too if found
    if (strlen(hiddenKey) > 0) {
        sprintf(path, "Software\\Classes\\CLSID\\%s", hiddenKey);
        DeleteKeyFull(HKEY_CURRENT_USER, path);
        DeleteKeyFull(HKEY_LOCAL_MACHINE, path);
        sprintf(path, "Software\\Classes\\Wow6432Node\\CLSID\\%s", hiddenKey);
        DeleteKeyFull(HKEY_CURRENT_USER, path);
        DeleteKeyFull(HKEY_LOCAL_MACHINE, path);
        printf("  [+] Deleted hidden key: %s\n", hiddenKey);
    }

    // --- Clear Registration Info ---
    printf("\n[*] Step 5/7 - Clearing registration info...\n");
    HKEY hKey;

    if (OpenRegKey(HKEY_CURRENT_USER, "Software\\DownloadManager",
        KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "FName");
        RegDeleteValueA(hKey, "LName");
        RegDeleteValueA(hKey, "Email");
        RegDeleteValueA(hKey, "Serial");
        RegCloseKey(hKey);
        printOK("Cleared HKCU registration info");
    } else printFail("HKCU\\DownloadManager not found");

    if (OpenRegKey(HKEY_LOCAL_MACHINE, "Software\\Internet Download Manager",
        KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "FName");
        RegDeleteValueA(hKey, "LName");
        RegDeleteValueA(hKey, "Email");
        RegDeleteValueA(hKey, "Serial");
        RegCloseKey(hKey);
        printOK("Cleared HKLM registration info");
    } else printFail("HKLM\\Internet Download Manager not found");

    if (OpenRegKey(HKEY_LOCAL_MACHINE,
        "Software\\Wow6432Node\\Internet Download Manager",
        KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "FName");
        RegDeleteValueA(hKey, "LName");
        RegDeleteValueA(hKey, "Email");
        RegDeleteValueA(hKey, "Serial");
        RegCloseKey(hKey);
        printOK("Cleared HKLM Wow6432 registration info");
    } else printFail("HKLM Wow6432 not found");

    // --- Write Fresh Trial Data ---
    printf("\n[*] Step 6/7 - Writing fresh 30-day trial data...\n");

    if (OpenRegKey(HKEY_CURRENT_USER, "Software\\DownloadManager",
        KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "Serial", 0, REG_SZ, (BYTE*)"", 1);
        RegCloseKey(hKey);
        printOK("Set fresh Serial value");
    }

    const char* trialKey = "{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}";
    sprintf(path, "Software\\Classes\\CLSID\\%s", trialKey);
    WriteScanskValue(HKEY_CURRENT_USER, path);
    WriteScanskValue(HKEY_LOCAL_MACHINE, path);
    sprintf(path, "Software\\Classes\\Wow6432Node\\CLSID\\%s", trialKey);
    WriteScanskValue(HKEY_CURRENT_USER, path);
    WriteScanskValue(HKEY_LOCAL_MACHINE, path);
    WriteScanskValue(HKEY_CURRENT_USER, "Software\\DownloadManager");
    printOK("Written fresh trial scansk values");

    // --- Lock Keys Again ---
    printf("\n[*] Step 7/7 - Locking keys...\n");
    for (int i = 0; i < numKeys; i++) {
        sprintf(path, "Software\\Classes\\CLSID\\%s", clsidKeys[i]);
        LockKey(HKEY_CURRENT_USER, path);
        LockKey(HKEY_LOCAL_MACHINE, path);
        sprintf(path, "Software\\Classes\\Wow6432Node\\CLSID\\%s", clsidKeys[i]);
        LockKey(HKEY_CURRENT_USER, path);
        LockKey(HKEY_LOCAL_MACHINE, path);
        printf("  [+] Locked: %s\n", clsidKeys[i]);
    }

    // --- Final Result ---
    printf("\n==========================================\n");
    if (success) {
        printf("   SUCCESS! IDM trial reset to 30 days!\n");
        printf("   Please restart IDM now.\n");
    } else {
        printf("   DONE WITH WARNINGS - check [-] lines\n");
        printf("   Make sure you ran as Administrator!\n");
    }
    printf("==========================================\n\n");

    printf("Press Enter to exit...\n");
    getchar();
    return 0;
}
