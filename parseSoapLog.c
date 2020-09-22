#include "parseSoapLog.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define BUFSIZE 131072

#define MIN(a,b) (((a)>(b))?(b):(a))
#define MAX(a,b) (((a)<(b))?(b):(a))
#define maybeStrdup(s) ((s)?strdup(s):NULL)

typedef struct linelist_s {
  char *line;
  struct linelist_s *next;
} *linelist;

// Add a line, containing a duplicate of the given string
void addline(linelist *l, char *line) {
  linelist *tmp = l;
  while (*tmp) {
    tmp = &((*tmp)->next);
  }
  //  fprintf(stderr, "addline(%s)\n", line);
  *tmp = (linelist)malloc(sizeof(struct linelist_s));
  (*tmp)->line = strdup(line);

  (*tmp)->next = NULL;
}

void freelinelist(linelist *l) {
  if (*l) {
    freelinelist(&((*l)->next));
    free((*l)->line);
    free(*l);
    *l=NULL;
  }
}

// Split into lines. Modifies buf and adds lines to the linelist
void splitlines(char *buf, linelist *l) {
  // fprintf(stderr, "Splitting buffer\n");
  char *p1=buf;
  char *p2, *p3;
  while (p1 && *p1) {
    p2 = strchr(p1, '\n');
    p3 = strchr(p1, '\r');
    if (p2 == NULL && p3 != NULL) {
      *p3 = '\0';
      p2 = p3 + 1;
    } else if (p2 != NULL && p3 != NULL) {
      *p2 = '\0';
      *p3 = '\0';
      p2 = MAX(p2, p3) + 1;
    } else if (p2 != NULL) {
      *p2 = '\0';
      p2++;
    }
    
    addline(l, p1);
    p1 = p2;
  }
}

typedef struct message_s {
  char dir;
  char timestamp[13];
  int len;
  linelist lines;
} *message;

// Returns a copy of a header value
char *findheader(linelist l, char *header) {
  char *searchString = (char *)malloc(strlen(header) + 3);
  strcpy(searchString, header);
  strcat(searchString, ": ");
  while (l && strncasecmp(l->line, searchString, strlen(searchString)) != 0) {
    l = l->next;
  }
  if (l) {
    char *r = (char *)malloc(strlen(l->line) - strlen(searchString) + 1);
    strcpy(r, l->line + strlen(searchString));
    return r;
  } else {
    return NULL;
  }
}

// Return a newly allocated string containing response status
char *findstatus(linelist l) {
  char *s = (char *)malloc(BUFSIZE);
  if (!strncmp(l->line, "HTTP/1.1 ", 9)) {
    if (sscanf(l->line + 9, "%s", s) == 1) {
      return s;
    }
  }
  return NULL;
}

// Return a newly allocated copy of the body
char *extractbody(linelist l) {
  char *body=NULL;
  while (l && strlen(l->line) > 0) {
    // fprintf(stderr, "Skipping line [%s]\n", l->line);
    l = l->next;
  }
  if (!l) {
    return NULL;
  }
  while (l && !strlen(l->line)) {
    // fprintf(stderr, "Skipping one line [%s]\n", l->line);
    l = l->next;
  }
  if (!l) {
    return NULL;
  }
  body=strdup(l->line);
  l = l->next;
  while (l) {
    body = (char *)realloc(body, strlen(body) + strlen(l->line) + 2);
    strcat(body, "\n");
    strcat(body, l->line);
    l = l->next;
  }
  return body;
}

void usage(char *progname)
{
  fprintf(stderr, "Usage: %s -g <group by (xpath)> -n \"<nsprefix:namespace ...>\" -o <outfile prefix> -t <tmp file> <file> ...\n", progname);
}

// Return a newly allocated message, read from the infile
message readonemessage(FILE *infile) {
  static char inbuf[BUFSIZE];
  int l;
  char c;
  message tmp=NULL;
  while (fgets(inbuf, sizeof(inbuf), infile)) {
    while ((l = strlen(inbuf)) > 0 && ((c = inbuf[l - 1]) == '\n' || c == '\r')) {
      inbuf[l - 1] = '\0';
    }
    if (!strlen(inbuf)) {
      continue;
    }
    tmp = (message)malloc(sizeof(struct message_s));
    tmp->lines=NULL;
    
    //  read header
    if (strlen(inbuf) < 29 || strncmp(inbuf, "####", 4) != 0) {
      fprintf(stderr, "Expected segment header\n");
      return 0;
    } 
    //  extract direction, timestamp, size
    if (sscanf(inbuf + 6, "%c %12s %d ####", &(tmp->dir), (tmp->timestamp), &(tmp->len)) != 3) {
      fprintf(stderr, "Unparseable segment header\n");
      return 0;
    }
    memset(inbuf, 0, sizeof(inbuf));
    if (fread(inbuf, 1, tmp->len, infile) != tmp->len) {
      fprintf(stderr, "Failed to read %d characters of packet content\n", tmp->len);
      return 0;
    }
    // printf("dir=%c time=%s len=%d\n", tmp->dir, tmp->timestamp, tmp->len);
    
    splitlines(inbuf, &(tmp->lines));
    break;
  }
  return tmp;
}

/**
 * (stolen from http://xmlsoft.org/examples/xpath1.c)
 * register_namespaces:
 * @xpathCtx:the pointer to an XPath context.
 * @nsList:the list of known namespaces in 
 *"<prefix1>=<href1> <prefix2>=href2> ..." format.
 *
 * Registers namespaces from @nsList in @xpathCtx.
 *
 * Returns 0 on success and a negative value otherwise.
 */
int
register_namespaces(xmlXPathContextPtr xpathCtx, const xmlChar* nsList) {
  xmlChar* nsListDup;
  xmlChar* prefix;
  xmlChar* href;
  xmlChar* next;

  nsListDup = xmlStrdup(nsList);
  if(nsListDup == NULL) {
    fprintf(stderr, "Error: unable to strdup namespaces list\n");
    return(-1);
  }

  next = nsListDup;
  while(next != NULL) {
    /* skip spaces */
    while((*next) == ' ') next++;
    if((*next) == '\0') break;

    /* find prefix */
    prefix = next;
    next = (xmlChar*)xmlStrchr(next, '=');
    if(next == NULL) {
      fprintf(stderr,"Error: invalid namespaces list format\n");
      xmlFree(nsListDup);
      return(-1);
    }
    *(next++) = '\0';

    /* find href */
    href = next;
    next = (xmlChar*)xmlStrchr(next, ' ');
    if(next != NULL) {
      *(next++) = '\0';
    }

    /* do register namespace */
    if(xmlXPathRegisterNs(xpathCtx, prefix, href) != 0) {
      fprintf(stderr,"Error: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", prefix, href);
      xmlFree(nsListDup);
      return(-1);
    }
  }

  xmlFree(nsListDup);
  return(0);
}

void printLogEntry(char *groupBy, char *nslist, char *outfilename, char *tmpfilename, char direction, char *timestamp, char *operation, char *status, xmlDoc *doc) {
  char *currentTransactionId = NULL;
  static char *lastTransactionId = NULL;
  static FILE *outfile = NULL;
  static char filename[BUFSIZE], inbuf[BUFSIZE];
  if (direction == '\0') {
    if (outfile) {
      fclose(outfile);
    }
    
    if (currentTransactionId) {
      free(currentTransactionId);
    }
    return;
  } else if (direction == '>') {
    if (doc && groupBy) {
      xmlXPathContextPtr context = xmlXPathNewContext(doc);
      if (nslist) {
	register_namespaces(context, (xmlChar *)nslist);
      }
      xmlXPathObjectPtr result = xmlXPathEvalExpression((xmlChar *)groupBy, context);
      
      if (result) {
	if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
	  xmlXPathFreeObject(result);
	  printf("No result\n");
	} else {
	  xmlChar *value = xmlNodeListGetString(doc, result->nodesetval->nodeTab[0]->xmlChildrenNode, 1);
	  currentTransactionId = strdup((char *)value);
	  xmlFree(value);
	}
      }
      if (result) {
	xmlXPathFreeObject(result);
      }
      if (context) {
	xmlXPathFreeContext(context);
      }
    }
  }
  if (currentTransactionId && (!lastTransactionId || strcmp(lastTransactionId, currentTransactionId))) {
    // printf("############## New transaction %s\n", currentTransactionId);
    lastTransactionId = currentTransactionId;
    if (outfile) {
      fclose(outfile);
    }
    snprintf(filename, sizeof(filename), "%s_%s_%s", outfilename, timestamp, currentTransactionId);
    filename[sizeof(filename)-1] = '\0';
    if (!(outfile=fopen(filename, "w"))) {
      perror(filename);
    }
  }
  if (outfile) {
    fprintf(outfile, "## %s %s (%s)\n", timestamp, (direction=='>')?"request":"response", (direction=='>')?(operation):(status));
    if (doc) {
      xmlKeepBlanksDefault(0);
      xmlLineNumbersDefault(1);
      xmlThrDefIndentTreeOutput(1);
      xmlSaveFormatFileEnc(tmpfilename, doc, "utf-8", 1);
      FILE *tmpfile = fopen(tmpfilename, "r");
      size_t n;
      while ((n = fread(inbuf, 1, sizeof(inbuf), tmpfile)) != 0) {
	fwrite(inbuf, 1, n, outfile);
      }
      fclose(tmpfile);
      unlink(tmpfilename);
    }
    fprintf(outfile, "\n");
  }
}

/*
 * Note: This is NOT the worst function I've ever written.
 */
int parseLogFile(char *filename, char *groupBy, char *nslist, char *outfilename, char *tmpfilename) {
  FILE *infile = fopen(filename, "r");
  message msg, newmsg;
  char *body=NULL;

  if (!infile) {
    perror(filename);
    return 0;
  }

  msg = readonemessage(infile);
  while (msg != NULL) {
    newmsg = NULL;
    // Sending to server
    if (msg->dir == '>') {
      char *SOAPAction = findheader(msg->lines, "SOAPAction");
      // fprintf(stderr, "SOAP Action: %s\n", SOAPAction);

      body = extractbody(msg->lines);

      // fprintf(stderr, "Handling any continuation packets in the same direction\n");
      while ((newmsg = readonemessage(infile)) != NULL) {
	if (newmsg->dir == msg->dir) {
	  linelist tmp = newmsg->lines;
	  while (tmp) {
	    if (body) {
	      body = (char *)realloc(body, strlen(body) + strlen(tmp->line) + 2);
	      // strcat(body, "\n");
	      strcat(body, tmp->line);
	    } else {
	      body = strdup(tmp->line);
	    }
	    tmp = tmp->next;
	  }
	  freelinelist(&(newmsg->lines));
	  free(newmsg);
	} else {
	  char *status = findstatus(newmsg->lines);
	  if (status && !strcmp(status, "100")) {
	    freelinelist(&(newmsg->lines));
	    free(newmsg);
	    newmsg=NULL;
	  } else {
	    break;
	  }
	}
      }      

      // printf("Request: %s %s\n[%s]\n", msg->timestamp, SOAPAction, body);

      xmlDoc *doc=NULL;
      if (body) {
	if (!(doc = xmlParseDoc((xmlChar*)body))) {
	  fprintf(stderr, "Parse error for timestamp %s, body [%s]\n", msg->timestamp, body);
	}
      }
      
      printLogEntry(groupBy, nslist, outfilename, tmpfilename, msg->dir, msg->timestamp, SOAPAction, NULL, doc);


      //      fprintf(stderr, "Ready, cleaning up\n");
      xmlFreeDoc(doc);
      if (SOAPAction) {
	free(SOAPAction);
      }
      freelinelist(&(msg->lines));
      free(msg);
      msg = newmsg;
    } else {
      char *status = findstatus(msg->lines);
      //fprintf(stderr, "Response status: %s\n", status);
      
      body = extractbody(msg->lines);
      // If the server keeps sending data, just merge it.
      while ((newmsg = readonemessage(infile)) != NULL && newmsg->dir == msg->dir) {
	//fprintf(stderr, "Continuation from server\n");
	linelist tmp = newmsg->lines;
	while (tmp) {
	  if (body) {
	    body = (char *)realloc(body, strlen(body) + strlen(tmp->line) + 2);
	    //	    strcat(body, "\n");
	    strcat(body, tmp->line);
	  } else {
	    body = strdup(tmp->line);
	  }
	  tmp = tmp->next;
	}
	// fprintf(stderr, "Merged message body\n");
	freelinelist(&(newmsg->lines));
	free(newmsg);
      }

      //printf("Response: %s status %s\n[%s]\n", msg->timestamp, status, body);

      xmlDoc *doc=NULL;
      if (body) {
	if (!(doc = xmlParseDoc((xmlChar*)body))) {
	  fprintf(stderr, "Parse error for timestamp %s, body [%s]\n", msg->timestamp, body);
	}
      }
      
      printLogEntry(groupBy, nslist, outfilename, tmpfilename, msg->dir, msg->timestamp, NULL, status, doc);

      xmlFreeDoc(doc);
      if (status) {
	free(status);
      }
      freelinelist(&(msg->lines));
      free(msg);
      msg = newmsg;
    }
		     
    if (body) {
      free(body);
    }
  }
  fclose(infile);
  return 1;
}


int main(int argc, char *argv[]) {
  // initialize stuff
  LIBXML_TEST_VERSION;
  int o;
  char *groupBy=NULL;
  char *nslist=NULL;
  char *outfilename = NULL;
  char *tmpfilename = NULL;
  FILE *outfile = stdout;
  
  while ((o=getopt(argc, argv, "g:n:o:t:")) != -1) {
    switch (o) {
    case 'g':
      groupBy=optarg;
      break;
    case 'n':
      nslist=optarg;
      break;
    case 'o':
      outfilename = optarg;
      break;
    case 't':
      tmpfilename = optarg;
      break;
    default:
      usage(argv[0]);
      return -1;
      break;
    }
  }

  if (!outfilename || !tmpfilename) {
    usage(argv[0]);
    return -1;
  }

  int i;
  for (i=optind; i < argc; i++) {
    if (!parseLogFile(argv[i], groupBy, nslist, outfilename, tmpfilename)) {
      break;
    }
  }
  printLogEntry(NULL, NULL, NULL, NULL, '\0', NULL, NULL, NULL, NULL);
  
  if (outfile) {
    fclose(outfile);
  }
  xmlCleanupParser();
  xmlMemoryDump();
  return(0);
}
