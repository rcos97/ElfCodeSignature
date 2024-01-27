#include <iostream>
#include <string.h>
#include "elfSignatureApi.h"

void printU8(char* out, unsigned int len){
  for(int i = 0; i < len; i++){
    printf("%02X", ((const unsigned char *)(out))[i]);
  }
  printf("\n");
}

int main(int argc, char const* argv[]){
  unsigned int textLen;
  int ret = ReadElfSection("../source/libtest.so", ".text", NULL, &textLen);
  if(ret != 1){
    std:: cout << "error"<<std::endl;
    return 0;
  }

  char out[textLen];
  ret = ReadElfSection("../source/libtest.so", ".text", out, &textLen);
  if(ret != 1){
    std:: cout << "error"<<std::endl;
    return 0;
  }
  printU8(out, textLen);

  AddElfSection("../source/libtest.so", ".aaa", "liba.so", out, textLen);
  AddElfSection("../source/liba.so", ".zzz", "liba.so", out, textLen);

  std::cout <<"********************************** sign ***********************************************"<<std::endl;
  unsigned char pub[65];
  char certificateFile[2048] = {0};
  unsigned int certificateFileLen = 0;
  GetBuffFromFile("../source/certificate.crt", certificateFile, &certificateFileLen);
  std:: cout << "read certificate :"<<std::endl;
  printU8(certificateFile, certificateFileLen);
  char certificateDer[2048] = {0};
  unsigned int certificateDerLen = 0;
  X509Pem2Der(certificateFile, certificateFileLen, certificateDer, &certificateDerLen);
  std:: cout << "certificate der :"<<std::endl;
  printU8(certificateDer, certificateDerLen);
  GetPublicKeyFromCertificate(certificateDer, certificateDerLen, pub);
  std:: cout << "publickey :"<<std::endl;
  printU8((char*)pub, 65);

  std:: cout <<"read file:"<<std:: endl;
  char p12File[2048] = {0};
  unsigned int p12FileLen = 0;
  ret = GetBuffFromFile("../source/rcos.pfx", p12File, &p12FileLen);
  printU8((char *)p12File, p12FileLen);
  unsigned char prikey[255];
  unsigned int priLen;
  ret = GetPriKeyFromP12(p12File,p12FileLen,"123456",prikey, &priLen);
  std:: cout <<"p12 get prikey:"<<std:: endl;
  printU8((char *)prikey, priLen);
  std::cout << "p12 get certificate:"<< std::endl;
  unsigned char x509[1000];
  unsigned int x509Len;
  ret = GetCertificateFromP12(p12File, p12FileLen,"123456",x509, &x509Len);
  printU8((char *)x509, x509Len);

  char pem[1000];
  unsigned int pemLen;
  X509Der2Pem((const char*)x509, x509Len,pem, &pemLen);
  std::cout << pem << std::endl;
  
  char digestInput[] = "1234";
  char digestOut[32] = {0};
  unsigned int digestOutLen;
  Digest(digestInput, strlen(digestInput), DigestAlg::sm3, digestOut, &digestOutLen);
  std::cout << "digest value:"<< std::endl;
  printU8((char *)digestOut, digestOutLen);
}