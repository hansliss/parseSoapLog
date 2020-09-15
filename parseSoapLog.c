#include "parseSoapLog.h"
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

int main(int argc, char *argv[]) {
  LIBXML_TEST_VERSION;

  // Do stuffs
  
  xmlCleanupParser();
  xmlMemoryDump();
  return(0);
}
