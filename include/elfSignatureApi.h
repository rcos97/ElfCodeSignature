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

enum DigestAlg{
  md5,
  sha1,
  sha256,
  sha512,
  sm3
};

FBC_API_PUBLIC
int ReadElfSection(const char* elfName, const char* sectionName, char* out, unsigned int* outLen);

FBC_API_PUBLIC
int AddElfSection(const char* elfName, const char* sectionName, const char* newElfName, char* context, unsigned int contextLen);

FBC_API_PUBLIC
int GetPublicKeyFromCertificate(const char* in, const unsigned int inLen, unsigned char* out);

/**
 * @brief Get the Buff From File object
 *  从文件中读取char数组
 * @param fileName 文件名
 * @param out char数组
 * @param outLen out的长度
 * @return 1成功 0失败
 */
FBC_API_PUBLIC
int GetBuffFromFile(const char* fileName, char* out, unsigned int* outLen);
/**
 * @brief Get the Pri Key From P 1 2 File object
 *  获取原始私钥从P12文件中
 *  如果out为NULL，outLen会输出原始私钥的长度
 * @param in p12数组
 * @param inlen in的长度
 * @param password p12文件密码
 * @param out 原始私钥
 * @param outLen 原始私钥的长度
 * @return 1 成功 0 失败 2 p12文件路径错误 3 p12文件密码不正确
 */
FBC_API_PUBLIC
int GetPriKeyFromP12(const char* in, const unsigned inlen, const char* password, unsigned char* out, unsigned int* outLen);

/**
 * @brief Get the Certificate From P 1 2 File object
 *   从P12数组中获取证书，der格式
 * @param in p12数组
 * @param inlen in的长度
 * @param password p12文件的密码
 * @param out 证书
 * @param outLen 证书长度
 * @return FBC_API_PUBLIC 
 */
FBC_API_PUBLIC
int GetCertificateFromP12(const char* in, const unsigned int inLen, const char* password, unsigned char* out, unsigned int* outLen);

FBC_API_PUBLIC
int X509Der2Pem(const char* in, const unsigned int inLen, char*out, unsigned int* outLen);

FBC_API_PUBLIC
int X509Pem2Der(const char* in, const unsigned int inLen, char*out, unsigned int* outLen);

FBC_API_PUBLIC
int Digest(const char* in, const unsigned int inLen, const DigestAlg alg, char* out, unsigned int* outLen);

#ifdef __cplusplus
}
#endif


#endif