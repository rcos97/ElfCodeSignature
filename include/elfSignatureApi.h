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

#ifdef __cplusplus
}
#endif


#endif