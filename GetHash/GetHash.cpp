#define _UNICODE 1
#define UNICODE 1

#include <iostream>
#include <fstream>
#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>
#include <Softpub.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include<mscat.h>
#include <ctime>
#include <time.h>
#include <filesystem>
#include <string>
#include <queue>
#include <thread>
#include <shlobj.h>

std::queue <char*> qdata;


#pragma comment (lib, "Crypt32")
#pragma comment (lib, "wintrust")
#pragma warning(disable : 4996) 

/// gethash
#define BUFSIZE 1024
#define MAX_PATH 1024
#define MD5LEN  16
namespace fs = std::experimental::filesystem;
using namespace std;

BOOL VerifySignature(LPCWSTR path);
char* gethash(TCHAR* filename)
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
    }

    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
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
        }
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        printf("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
    }

    CHAR hash[33];
    hash[32] = NULL;
    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {

        for (DWORD i = 0; i < cbHash; i++)
        {
            printf("%c%c", rgbDigits[rgbHash[i] >> 4],
                rgbDigits[rgbHash[i] & 0xf]);
            hash[i * 2] = rgbDigits[rgbHash[i] >> 4];
            hash[i * 2 + 1] = rgbDigits[rgbHash[i] & 0xf];
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


    return hash;
}



bool checkFilePE(TCHAR* filepath) {


    HANDLE hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
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

void checkDir(TCHAR* dir, string filecsv)
{
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    TCHAR filepath[MAX_PATH];
    TCHAR directory[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;
    _tprintf(TEXT("\nFolder: %s\n\n"), dir);



    StringCchCopy(szDir, MAX_PATH, dir);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
    StringCchCopy(directory, MAX_PATH, dir);
    StringCchCat(directory, MAX_PATH, TEXT("\\"));

    // Find the first file in the directory.
    hFind = FindFirstFile(szDir, &ffd);

    char* hashfile;
    do
    {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))   // if not directory
        {


            StringCchCopy(filepath, MAX_PATH, directory);
            StringCchCat(filepath, MAX_PATH, ffd.cFileName);
            //HANDLE hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

            if (checkFilePE(filepath)) {
                if (!VerifySignature(filepath)) {
                    _tprintf(TEXT("%s     "), ffd.cFileName);

                    int size = WideCharToMultiByte(CP_UTF8, 0, filepath, -1, NULL, 0, NULL, NULL);

                    char* charString = new char[size + 33];


                    // Convert _TCHAR to char and write csv
                    WideCharToMultiByte(CP_UTF8, 0, filepath, -1, charString, size, NULL, NULL);
                    char* hashfile = gethash(filepath);

                    strncat(charString, ",", 1);
                    strncat(charString, hashfile, 32);
                    qdata.push(charString);

                }

            }
        }
        else {
            StringCchCopy(filepath, MAX_PATH, directory);
            StringCchCat(filepath, MAX_PATH, ffd.cFileName);
            if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) {
                // Nếu là thư mục gốc hoặc thư mục cha
                continue;
            }
            else {
                // Nếu không phải là thư mục gốc hoặc thư mục cha
              // checkDir(filepath, filecsv);
            }
        }
    } while (FindNextFile(hFind, &ffd) != 0); // check next file


    FindClose(hFind);

    //char time1[80];
    //std::time_t currentTime1 = std::time(nullptr);

    //std::strftime(time1, sizeof(time1), "%Y%m%d_%H%M%S", std::localtime(&currentTime1));
   // cout << time1 << "\n";

    return;
}

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


int _tmain(int argc, _TCHAR* argv[]) {

    std::time_t currentTime = std::time(nullptr);

    // Chuyển đổi thời gian thành chuỗi định dạng
    char time[80];
    std::strftime(time, sizeof(time), "%Y%m%d_%H%M%S", std::localtime(&currentTime));
    //std::cout << "Thời gian hiện tại: " << time << std::endl;
    //cout << time;
    std::string directoryPath = "C:\\gethash";
    CreateDirectory(L"C:\gethash", NULL);
    std::string filename = "C:\\gethash\\" + std::string(time) + ".csv";
    CreateDirectory(L"C:\gethash", NULL);

    std::ofstream csvFile(filename);
    if (!csvFile.is_open()) {
        std::cerr << "Run as administrator\n";
        return 1;
    }
    csvFile.close();


    if (argc == 1)
    {
        printf("Code by truongnh \n");
        printf("-s :   %s\n", "system32 , syswow64, SystemDrive, downloads ");
        printf("-fp :   %s\n", "filepath");
        printf("comandline : -fp filepath \n  for example check folder D:\\user\\truongnh: GetHash.exe -fp D:\\user\\truongnh \n");

    }


    else {
        if (_tcscmp(argv[1], _T("-s")) == 0)
        {
            printf("-s :   %s\n", "Folder: system32 , syswow64, SystemDrive, downloads  ");

            char sDrive[MAX_PATH];
            int result = GetWindowsDirectoryA(sDrive, MAX_PATH);
            TCHAR* dirSystemDrive = new TCHAR[result + 1];

            MultiByteToWideChar(CP_ACP, 0, sDrive, MAX_PATH, dirSystemDrive, result);
            dirSystemDrive[result] = '\0';

            PWSTR sdownload;
            int result1 = SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &sdownload);

            TCHAR dirDownloads[MAX_PATH];
            _tcscpy(dirDownloads, sdownload);

            TCHAR dirSystem32[1024] = _T("C:\\windows\\system32");
            TCHAR dirSyswow64[1024] = _T("C:\\windows\\syswow64");
            std::thread syswow64(checkDir, dirSyswow64, filename);
            std::thread system32(checkDir, dirSystem32, filename);

            //(dirSystem32, filename); 
            //checkDir(dirSyswow64, filename);
            syswow64.join(); //system32 chay lau hon syswow64

            std::thread systemDrive(checkDir, dirSystemDrive, filename);
            std::thread dowloads(checkDir, dirDownloads, filename);
            systemDrive.join();
            dowloads.join();

            system32.join();

            std::ofstream csvFile(filename, std::ios::app);

            while (!qdata.empty())
            {
                csvFile << qdata.front();
                csvFile << "\n";

                qdata.pop();
            }
            csvFile.close();

        }

        if (_tcscmp(argv[1], _T("-fp")) == 0)
        {
            TCHAR filepath[MAX_PATH] = _T("");
            
            if (argc >= 3) {
                _tcsncat(filepath, argv[2], 1024);
                for (int i = 3; i < argc; i++) {
                    _tcsncat(filepath, _T(" "), 1024);
                    _tcsncat(filepath, argv[i], 1024);

                }
                checkDir(filepath, filename);

            }

        }
        std::ofstream csvFile(filename, std::ios::app);

        while (!qdata.empty())
        {
            csvFile << qdata.front();
            csvFile << "\n";

            qdata.pop();
        }
        csvFile.close();

        cout<<"file output:  " << filename;
    }

    return 0;
}