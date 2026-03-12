// This file is part of Notepad++ project
// Copyright (C)2025 Don HO <don.h@free.fr>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "SecureStorage.h"

#include <Aclapi.h>
#include <ShlObj.h>
#include <fstream>
#include <vector>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

namespace {

std::wstring getStoragePathForCsidl(int csidl) {
  wchar_t basePath[MAX_PATH] = {};
  if (FAILED(SHGetFolderPath(nullptr, csidl, nullptr, 0, basePath))) {
    return L"";
  }

  return std::wstring(basePath) + L"\\Notepad++\\AIAssistant";
}

bool ensureDirectoryTreeExists(const std::wstring &storagePath) {
  if (storagePath.empty()) {
    return false;
  }

  const size_t splitPos = storagePath.find_last_of(L"\\/");
  if (splitPos == std::wstring::npos) {
    return false;
  }

  const std::wstring parentPath = storagePath.substr(0, splitPos);
  CreateDirectory(parentPath.c_str(), nullptr);
  CreateDirectory(storagePath.c_str(), nullptr);

  const DWORD attrs = GetFileAttributes(storagePath.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool buildAclForCurrentUser(std::vector<BYTE> &userSidBuffer, PACL &acl) {
  acl = nullptr;

  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return false;
  }

  DWORD tokenInfoSize = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &tokenInfoSize);
  if (tokenInfoSize == 0) {
    CloseHandle(token);
    return false;
  }

  userSidBuffer.resize(tokenInfoSize);
  if (!GetTokenInformation(token, TokenUser, userSidBuffer.data(),
                           tokenInfoSize, &tokenInfoSize)) {
    CloseHandle(token);
    return false;
  }
  CloseHandle(token);

  auto *tokenUser = reinterpret_cast<TOKEN_USER *>(userSidBuffer.data());

  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  PSID adminSid = nullptr;
  PSID systemSid = nullptr;

  if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                &adminSid)) {
    return false;
  }

  if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0,
                                0, 0, 0, 0, 0, 0, &systemSid)) {
    FreeSid(adminSid);
    return false;
  }

  EXPLICIT_ACCESSW entries[3] = {};
  const PSID sids[3] = {tokenUser->User.Sid, systemSid, adminSid};
  for (int i = 0; i < 3; ++i) {
    entries[i].grfAccessPermissions = FILE_ALL_ACCESS;
    entries[i].grfAccessMode = SET_ACCESS;
    entries[i].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[i].Trustee.ptstrName = static_cast<LPWSTR>(sids[i]);
  }
  entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
  entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  entries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;

  const DWORD aclResult = SetEntriesInAclW(3, entries, nullptr, &acl);
  FreeSid(systemSid);
  FreeSid(adminSid);

  return aclResult == ERROR_SUCCESS;
}

void applyStorageAcl(const std::wstring &storagePath) {
  std::vector<BYTE> userSidBuffer;
  PACL acl = nullptr;
  if (!buildAclForCurrentUser(userSidBuffer, acl)) {
    return;
  }

  SetNamedSecurityInfoW(const_cast<LPWSTR>(storagePath.c_str()), SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION |
                            PROTECTED_DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, acl, nullptr);
  if (acl) {
    LocalFree(acl);
  }
}

bool fileExists(const std::wstring &filePath) {
  const DWORD attrs = GetFileAttributes(filePath.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES &&
         (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

} // namespace

std::wstring SecureStorage::getStoragePath() {
  const std::wstring path = getStoragePathForCsidl(CSIDL_LOCAL_APPDATA);
  if (ensureDirectoryTreeExists(path)) {
    applyStorageAcl(path);
    return path;
  }

  return L"";
}

std::wstring SecureStorage::getLegacyStoragePath() {
  return getStoragePathForCsidl(CSIDL_APPDATA);
}

std::wstring SecureStorage::getKeyFilePath(const std::wstring &keyName) {
  return getKeyFilePath(getStoragePath(), keyName);
}

std::wstring SecureStorage::getKeyFilePath(const std::wstring &storagePath,
                                           const std::wstring &keyName) {
  if (storagePath.empty()) {
    return L"";
  }

  return storagePath + L"\\" + keyName + L".key";
}

std::vector<BYTE> SecureStorage::encrypt(const std::wstring &data) {
  std::vector<BYTE> encrypted;

  if (data.empty())
    return encrypted;

  const BYTE *dataBytes = reinterpret_cast<const BYTE *>(data.c_str());
  DWORD dataSize = static_cast<DWORD>((data.length() + 1) * sizeof(wchar_t));

  DATA_BLOB inputBlob = {};
  inputBlob.pbData = const_cast<BYTE *>(dataBytes);
  inputBlob.cbData = dataSize;

  DATA_BLOB outputBlob = {};
  if (CryptProtectData(&inputBlob,
                       L"NppAIKey",               // Description
                       nullptr,                   // Optional entropy
                       nullptr,                   // Reserved
                       nullptr,                   // Optional prompt struct
                       CRYPTPROTECT_UI_FORBIDDEN, // No UI
                       &outputBlob)) {
    encrypted.assign(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    LocalFree(outputBlob.pbData);
  }

  return encrypted;
}

std::wstring SecureStorage::decrypt(const std::vector<BYTE> &data) {
  if (data.empty())
    return L"";

  DATA_BLOB inputBlob = {};
  inputBlob.pbData = const_cast<BYTE *>(data.data());
  inputBlob.cbData = static_cast<DWORD>(data.size());

  DATA_BLOB outputBlob = {};
  LPWSTR description = nullptr;

  if (CryptUnprotectData(&inputBlob, &description,
                         nullptr,                   // Optional entropy
                         nullptr,                   // Reserved
                         nullptr,                   // Optional prompt struct
                         CRYPTPROTECT_UI_FORBIDDEN, // No UI
                         &outputBlob)) {
    std::wstring result = reinterpret_cast<wchar_t *>(outputBlob.pbData);
    LocalFree(outputBlob.pbData);
    if (description)
      LocalFree(description);
    return result;
  }

  return L"";
}

bool SecureStorage::writeToFile(const std::wstring &filePath,
                                const std::vector<BYTE> &data) {
  std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
  if (!file.is_open())
    return false;

  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  file.close();

  return true;
}

std::vector<BYTE> SecureStorage::readFromFile(const std::wstring &filePath) {
  std::vector<BYTE> data;

  std::ifstream file(filePath, std::ios::binary | std::ios::ate);
  if (!file.is_open())
    return data;

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  data.resize(static_cast<size_t>(size));
  file.read(reinterpret_cast<char *>(data.data()), size);
  file.close();

  return data;
}

bool SecureStorage::saveApiKey(const std::wstring &keyName,
                               const std::wstring &value) {
  if (keyName.empty())
    return false;

  const std::wstring filePath = getKeyFilePath(keyName);
  if (filePath.empty())
    return false;

  if (value.empty()) {
    return deleteApiKey(keyName);
  }

  std::vector<BYTE> encrypted = encrypt(value);
  if (encrypted.empty())
    return false;

  const bool saved = writeToFile(filePath, encrypted);
  if (saved) {
    const std::wstring legacyPath = getKeyFilePath(getLegacyStoragePath(), keyName);
    if (!legacyPath.empty()) {
      DeleteFile(legacyPath.c_str());
    }
  }

  return saved;
}

std::wstring SecureStorage::loadApiKey(const std::wstring &keyName) {
  if (keyName.empty())
    return L"";

  const std::wstring localPath = getKeyFilePath(keyName);
  if (localPath.empty())
    return L"";

  if (fileExists(localPath)) {
    const std::vector<BYTE> encrypted = readFromFile(localPath);
    if (encrypted.empty())
      return L"";

    return decrypt(encrypted);
  }

  const std::wstring legacyPath = getKeyFilePath(getLegacyStoragePath(), keyName);
  if (!fileExists(legacyPath)) {
    return L"";
  }

  const std::vector<BYTE> encrypted = readFromFile(legacyPath);
  if (encrypted.empty()) {
    return L"";
  }

  if (writeToFile(localPath, encrypted)) {
    DeleteFile(legacyPath.c_str());
  }

  return decrypt(encrypted);
}

bool SecureStorage::deleteApiKey(const std::wstring &keyName) {
  if (keyName.empty())
    return false;

  bool deleted = false;

  const std::wstring localPath = getKeyFilePath(keyName);
  if (!localPath.empty() && fileExists(localPath)) {
    deleted = DeleteFile(localPath.c_str()) != 0 || deleted;
  }

  const std::wstring legacyPath = getKeyFilePath(getLegacyStoragePath(), keyName);
  if (!legacyPath.empty() && fileExists(legacyPath)) {
    deleted = DeleteFile(legacyPath.c_str()) != 0 || deleted;
  }

  return deleted;
}

bool SecureStorage::hasApiKey(const std::wstring &keyName) {
  if (keyName.empty())
    return false;

  const std::wstring localPath = getKeyFilePath(keyName);
  if (!localPath.empty() && fileExists(localPath)) {
    return true;
  }

  const std::wstring legacyPath = getKeyFilePath(getLegacyStoragePath(), keyName);
  return !legacyPath.empty() && fileExists(legacyPath);
}

std::wstring SecureStorage::loadLegacyValue(const std::wstring &keyName) {
  if (keyName.empty()) {
    return L"";
  }

  const std::wstring legacyPath = getKeyFilePath(getLegacyStoragePath(), keyName);
  if (legacyPath.empty() || !fileExists(legacyPath)) {
    return L"";
  }

  const std::vector<BYTE> encrypted = readFromFile(legacyPath);
  if (encrypted.empty()) {
    return L"";
  }

  return decrypt(encrypted);
}
