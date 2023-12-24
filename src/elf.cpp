#include "LIEF/LIEF.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/span.hpp"
#include "elfSignatureApi.h"

int ReadElfSection(const char* elfName, const char* sectionName, char* out, unsigned int* outLen){
  if(elfName == NULL || sectionName == NULL || outLen == NULL){
    return 0;
  }

  std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(elfName);
  if(elf == NULL){
    return 0;
  }

  LIEF::ELF::Section* section = elf->get_section(sectionName);
  if(section == NULL){
    return 0;
  }

  LIEF::span<const uint8_t> sectionContent = section->content();
  *outLen = sectionContent.size();
  if(out == NULL){
    return 1;
  }

  const uint8_t* ptr = sectionContent.data();
  memcpy(out, ptr, *outLen);

  return 1;
}

int AddElfSection(const char* elfName, const char* sectionName, const char* newElfName, char* context, unsigned int contextLen){

  std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(elfName);
  if(elf == NULL){
    return 0;
  }

  LIEF::ELF::Section mySection{std::string(sectionName)};

  std::vector<uint8_t> data((uint8_t *)context, (uint8_t*)(context + contextLen));

  mySection.content(std::move(data));
  elf->add(mySection);
  elf->write(newElfName);
}