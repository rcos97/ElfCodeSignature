#ifndef ELF_SIGNAUTRE_API_H
#define ELF_SIGNAUTRE_API_H

#ifndef stdcall
#ifdef _WIN32
#define stdcall __stdcall
#else
#define stdcall
#endif  // win32
#endif

#ifdef __cplusplus
extern "C" {
#endif
#if defined(__linux__) || defined(__APPLE__)
#define FBC_API_PUBLIC __attribute__((visibility("default")))
#else
#define FBC_API_PUBLIC __declspec(dllexport)
#endif  //_linux

FBC_API_PUBLIC
int ReadElfSection(const char* elfName, const char* sectionName, char* out, unsigned int* outLen);

FBC_API_PUBLIC
int AddElfSection(const char* elfName, const char* sectionName, const char* newElfName, char* context, unsigned int contextLen);

FBC_API_PUBLIC
int GetPublicKeyFromCertificate(const char* filePath, unsigned char* out);

/**
 * @brief Get the Pri Key From P 1 2 File object
 *  获取原始私钥从P12文件中
 *  如果out为NULL，outLen会输出原始私钥的长度
 * @param filePath p12文件路径
 * @param password p12文件密码
 * @param out 原始私钥
 * @param outLen 原始私钥的长度
 * @return 1 成功 0 失败 2 p12文件路径错误 3 p12文件密码不争取
 */
FBC_API_PUBLIC
int GetPriKeyFromP12File(const char* filePath, const char* password, unsigned char* out, unsigned int* outLen);

#ifdef __cplusplus
}
#endif


#endif