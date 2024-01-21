#include <iostream>
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
  unsigned char pub[65];
  GetPublicKeyFromCertificate("../source/certificate.crt", pub);
  std:: cout << "publickey :"<<std::endl;
  printU8((char*)pub, 65);

  unsigned char prikey[255];
  unsigned int priLen;
  ret = GetPriKeyFromP12File("../source/rcos.pfx","123456",prikey, &priLen);
  std::cout << ret << std::endl;
  printU8((char *)prikey, priLen);

  std::cout << "p12 get certificate:"<< std::endl;
  unsigned char x509[1000];
  unsigned int x509Len;
  ret = GetCertificateFromP12File("../source/rcos.pfx","123456",x509, &x509Len);
  std::cout << ret << std::endl;
  printU8((char *)x509, x509Len);

  char pem[1000];
  unsigned int pemLen;
  X509Der2Pem((const char*)x509, x509Len,pem, &pemLen);
  std::cout << pem << std::endl;
}