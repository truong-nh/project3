#define _UNICODE 1
#define UNICODE 1

#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>
#include <Softpub.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include<mscat.h>
#include <iostream>
#include <iostream>

#pragma comment (lib, "Crypt32")
#pragma comment (lib, "wintrust")


/// gethash
#define BUFSIZE 1024
#define MD5LEN  16
BOOL VerifySignature(LPCWSTR path);
DWORD gethash(TCHAR* filename)
{

    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    //LPCWSTR filename = L"D:\\HUST\\20231\\Project3\\svchost.exe";
    // Logic to check usage goes here.

    hFile = CreateFile(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        printf("Error opening file %s\nError: %d\n", filename,
            dwStatus);
        return dwStatus;
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        printf("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return dwStatus;
    }

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        //printf("MD5 hash of file %s is: ", filename);
        for (DWORD i = 0; i < cbHash; i++)
        {
            printf("%c%c", rgbDigits[rgbHash[i] >> 4],
                rgbDigits[rgbHash[i] & 0xf]);
        }
        printf("\n");
    }
    else
    {
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);


    return dwStatus;
}


BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;

    WinTrustData.dwUIContext = 0;

    WinTrustData.pFile = &FileData;


    lStatus = WinVerifyTrust(NULL,&WVTPolicyGUID,&WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
       
        return false;
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            wprintf_s(L"The file \"%s\" is not signed.\n",
                pwszSourceFile);
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            wprintf_s(L"An unknown error occurred trying to "
                L"verify the signature of the \"%s\" file.\n",
                pwszSourceFile);
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        wprintf_s(L"The signature is present, but specifically "
            L"disallowed.\n");
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        wprintf_s(L"The signature is present, but not "
            L"trusted.\n");
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
            L"representing the subject or the publisher wasn't "
            L"explicitly trusted by the admin and admin policy "
            L"has disabled user trust. No signature, publisher "
            L"or timestamp errors.\n");
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        wprintf_s(L"Error is: 0x%x.\n",
            lStatus);
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return true;
}


bool checkFilePE(HANDLE hFile) {



    if (hFile != INVALID_HANDLE_VALUE) {
        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead;

        //offset 0x00 ->0x02 is e_magic . file PE has e_maigc = 0x5D4A ='MZ'
        if (ReadFile(hFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL)) {
            if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {     //IMAGE_DOS_SIGNATURE = 0x5D4A  
                return true;
            }

        }
    }

    return false;
}

void checkDir(TCHAR* dir)
{
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    TCHAR filepath[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;

    _tprintf(TEXT("\n ------------------------------------\n\n"));
    _tprintf(TEXT("\n ------------------------------------\n\n"));

    _tprintf(TEXT("\n ------------------------------------\n\n"));

    _tprintf(TEXT("\n ------------------------------------\n\n"));

    _tprintf(TEXT("\n ra soat thu muc: %s\n\n"), dir);



    StringCchCopy(szDir, MAX_PATH, dir);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
    StringCchCat(dir, MAX_PATH, TEXT("\\"));

    // Find the first file in the directory.
    hFind = FindFirstFile(szDir, &ffd);


    do
    {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))   // if not directory
        {


            StringCchCopy(filepath, MAX_PATH, dir);
            StringCchCat(filepath, MAX_PATH, ffd.cFileName);
            HANDLE hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

            if (checkFilePE(hFile)) {
                if (!VerifySignature(filepath)) {
                   // filesize.LowPart = ffd.nFileSizeLow;
                   // filesize.HighPart = ffd.nFileSizeHigh;
                    _tprintf(TEXT("  %s   \n"), ffd.cFileName);
                    gethash(filepath);

                }

            }
        }
    } while (FindNextFile(hFind, &ffd) != 0); // check next file


    FindClose(hFind);
    return;
}

/*
int checkCatlog() {
    LPBYTE lpHash;

    DWORD dwHashSize;



    if (CalcCatHash(lpPath, &dwHashSize, &lpHash))

    {

        HANDLE hCatalogContext = CryptCATAdminEnumCatalogFromHash(hHandle, lpHash, dwHashSize, 0, NULL);

        if (NULL != hCatalogContext)

        {
            
            CryptCATAdminEnumCatalogFromHash(hHandle, hCatalogContext, 0);

            nResult = 2;

        }



        LocalFree(lpHash);

        lpHash = NULL;

    }
}
*/

/*
bool verifyembeddedsignature(LPCWSTR pwszsourcefile)
{
    long lstatus;
    
    GUID wintrustverifyguid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    GUID driveractionguid = DRIVER_ACTION_VERIFY;
    HANDLE hfile;
    DWORD dwhash;
    byte bhash[100];
    HCATINFO hcatinfo;
    HCATADMIN hcatadmin;

    WINTRUST_DATA    wd = { 0 };
    WINTRUST_FILE_INFO wfi = { 0 };
    WINTRUST_CATALOG_INFO wci = { 0 };

    ////set up structs to verify files with cert signatures
    memset(&wfi, 0, sizeof(wfi));
    wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
    wfi.pcwszFilePath = pwszsourcefile;
    wfi.hFile = NULL;
    wfi.pgKnownSubject = NULL;

    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &wfi;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;   
    wd.dwStateAction = 0;
    wd.dwProvFlags = WTD_SAFER_FLAG;
    wd.hWVTStateData = NULL;
    wd.pwszURLReference = NULL;
    wd.pPolicyCallbackData = NULL;
    wd.pSIPClientData = NULL;
    wd.dwUIContext = 0;

    lstatus = WinVerifyTrust(NULL, &wintrustverifyguid, &wd);

    ////if failed, try to verify using catalog files
    if (lstatus != ERROR_SUCCESS)
    {
        //open the file
        hfile = CreateFileW(pwszsourcefile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hfile == INVALID_HANDLE_VALUE)
            return false;

        dwhash = sizeof(bhash);
        if (!CryptCATAdminCalcHashFromFileHandle(hfile, &dwhash, bhash, 0))
        {
            CloseHandle(hfile);
            return false;
            
        }

        //create a string form of the hash (used later in pszmembertag)
        

        if (!CryptCATAdminAcquireContext(&hcatadmin, &driveractionguid, 0))
        {
            CloseHandle(hfile);
            return false;
        }

       

        if (!CryptCATAdminAcquireContext(&hcatadmin, &driveractionguid, 0))
        {
            CloseHandle(hfile);
            return false;
        }

        //find the catalog which contains the hash
        hcatinfo = CryptCATAdminEnumCatalogFromHash(hcatadmin, bhash, dwhash, 0, NULL);
        
        if (hcatinfo)
        {
            CATALOG_INFO ci = { 0 };
            
            CryptCATCatalogInfoFromContext(hcatinfo, &ci, 0);
            
     

            wd.cbstruct = sizeof(wintrust_data);
            wd.dwunionchoice = wtd_choice_catalog;
            wd.pcatalog = &wci;
            wd.dwuichoice = wtd_ui_none;
            wd.fdwrevocationchecks = wtd_stateaction_verify;
            wd.dwprovflags = 0;
            wd.hwvtstatedata = null;
            wd.pwszurlreference = null;
            wd.ppolicycallbackdata = null;
            wd.psipclientdata = null;
            wd.dwuicontext = 0;

            memset(&wci, 0, sizeof(wci));
            wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
            wci.pcwszCatalogFilePath = ci.wszCatalogFile;
            wci.pcwszMemberFilePath = pwszsourcefile;
            wci.pcwszMemberTag = pszmembertag;psmembertag

            memset(&wd, 0, sizeof(wd));
            wd.cbStruct = sizeof(wintrust_data);
            wd.dwUnionChoice = wtd_choice_catalog;
            wd.pCatalog = &wci;
            wd.dwUIChoice = wtd_ui_none;
            wd.fdwRevocationChecks = wtd_stateaction_verify;
            wd.dwProvFlags = 0;
            wd.hWVTStateData = null;
            wd.pwszURLReference = null;
            wd.pPolicyCallbackData = null;
            wd.pSIPClientData = null;
            wd.dwUIContext = 0;

            lstatus = winverifytrust(null, &wintrustverifyguid, &wd);

            cryptcatadminreleasecatalogcontext(hcatadmin, hcatinfo, 0);
        }


        cryptcatadminreleasecontext(hcatadmin, 0);
        delete[] pszmembertag;
        closehandle(hfile);
    }

    if (lstatus != error_success)
        return false;
    else
        return true;
}
*/

BOOL VerifySignature(LPCWSTR path) //We will receive the char* filepath not wchar*
{
    //USES_CONVERSION;
    LPCWSTR pwszSourceFile = path; //We convert the char* to wchar*
    LONG lStatus;
    GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
    HANDLE hFile;
    DWORD dwHash;
    BYTE bHash[100];
    HCATINFO hCatInfo;
    HCATADMIN hCatAdmin;

    WINTRUST_DATA wd = { 0 };
    WINTRUST_FILE_INFO wfi = { 0 };
    WINTRUST_CATALOG_INFO wci = { 0 };

    ////set up structs to verify files with cert signatures
    wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
    wfi.pcwszFilePath = pwszSourceFile;
    wfi.hFile = NULL;
    wfi.pgKnownSubject = NULL;

    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.pPolicyCallbackData = NULL;
    wd.pSIPClientData = NULL;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &wfi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.hWVTStateData = NULL;
    wd.pwszURLReference = NULL;
    wd.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
    wd.dwUIContext = 0;
    wd.pSignatureSettings = 0;


    lStatus = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &WintrustVerifyGuid, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &WintrustVerifyGuid, &wd); //close hWVTStateData

    ////if failed, try to verify using catalog files
    if (lStatus != ERROR_SUCCESS)
    {
        //open the file
        hFile = CreateFileW(pwszSourceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return FALSE;

        dwHash = sizeof(bHash);
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHash, bHash, 0))
        {
            CloseHandle(hFile);
            return FALSE;
        }

        //Create a string form of the hash (used later in pszMemberTag)
        LPWSTR pszMemberTag = new WCHAR[dwHash * 2 + 1];
        for (DWORD dw = 0; dw < dwHash; ++dw)
        {
            wsprintfW(&pszMemberTag[dw * 2], L"%02X", bHash[dw]);
        }

        if (!CryptCATAdminAcquireContext(&hCatAdmin, &DriverActionGuid, 0))
        {
            CloseHandle(hFile);
            return FALSE;
        }

        //find the catalog which contains the hash
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL);

        if (hCatInfo)
        {
            CATALOG_INFO ci = { 0 };
            CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0);

            memset(&wci, 0, sizeof(wci));
            wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
            wci.pcwszCatalogFilePath = ci.wszCatalogFile;
            wci.pcwszMemberFilePath = pwszSourceFile;
            wci.hMemberFile = hFile;
            wci.pcwszMemberTag = pszMemberTag;
            wci.pbCalculatedFileHash = bHash;
            wci.cbCalculatedFileHash = dwHash;
            wci.hCatAdmin = hCatAdmin;

            memset(&wd, 0, sizeof(wd));
            wd.cbStruct = sizeof(WINTRUST_DATA);
            wd.pPolicyCallbackData = NULL;
            wd.pSIPClientData = NULL;
            wd.dwUIChoice = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice = WTD_CHOICE_CATALOG;
            wd.pCatalog = &wci;
            wd.dwStateAction = WTD_STATEACTION_VERIFY;
            wd.hWVTStateData = NULL;
            wd.pwszURLReference = NULL;
            wd.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
            wd.dwUIContext = 0;
            wd.pSignatureSettings = 0;

            lStatus = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &WintrustVerifyGuid, &wd);
            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &WintrustVerifyGuid, &wd); //close hWVTStateData
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }


        CryptCATAdminReleaseContext(hCatAdmin, 0);
        delete[] pszMemberTag;
        CloseHandle(hFile);
    }

    return (lStatus == ERROR_SUCCESS);
}


int _tmain(int argc, _TCHAR* argv[]){
    
    if (argc == 1)
    {
        printf("Code by truongnh \n");

        printf("-s :   %s\n", "system32 và syswow64 ");
        printf("-fp :   %s\n", "filepath");

        printf("-a :   %s\n", " ");
    }

    else {
        if (_tcscmp(argv[1], _T("-s")) == 0)
        {
            printf("-s :   %s\n", "lua chon ra soat s ");

        }

        if (_tcscmp(argv[1], _T("-e")) == 0)
        {
            printf("-fp :   %s\n", "lua chon ra soat e");

        }

        if (_tcscmp(argv[1], _T("-fp")) == 0)
        {
            _tprintf(_T("ra soat thu muc :   %d\n"), argc);

            printf("-fp :   %s\n", "lua chon ra soat thu muc");
            printf("comandline : -fp filepath \nvd ra soat thu muc truongnh và truongnh1: GetHash.exe -fp D:\\user\\truongnh D:\\user\\truongnh1 \n");
            if (argc > 2) {
                _tprintf(_T("ra soat thu muc :   %s\n"), _T("system32"));

                _tprintf(_T("ra soat thu muc :   %s\n"), _T("syswow64"));

                for (int i = 2; i < argc; i++) {
                    _tprintf(_T("ra soat thu muc :   %s\n"), argv[i]);
                }
            }

        }


        //TCHAR dirSystem32[1024] = _T("C:\\windows\\system32");
        //TCHAR dirSyswow64[1024] = _T("C:\\windows\\syswow64");

        //checkDir(dirSystem32);
        //checkDir(dirSyswow64);
    }
    

   //  TCHAR dirproject[1024] = _T("D:\\HUST\\20231\\Project3");

    // TCHAR filepath[1024] = _T("D:\\HUST\\20231\\Project3\\GetHash.exe");

    
    //checkDir(dirproject);
}