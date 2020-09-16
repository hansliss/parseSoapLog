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

typedef struct logInfo_s {
  char *timestamp;
  char *transactionId;
  char direction;
  char *operation;
  char *status;
  char *xml;
  xmlDoc *doc;
  struct logInfo_s *next;
} *logInfo;

void addlogentry(logInfo *loglist, char *timestamp, char *transactionId, char dir, char *status, char *SOAPAction, char *body) {
  logInfo *tmp = loglist;
  while (*tmp) {
    tmp = &((*tmp)->next);
  }
  *tmp = (logInfo)malloc(sizeof(struct logInfo_s)); 
  (*tmp)->timestamp = maybeStrdup(timestamp);
  (*tmp)->transactionId = maybeStrdup(transactionId);
  (*tmp)->direction = dir;
  (*tmp)->status = maybeStrdup(status);
  (*tmp)->operation = maybeStrdup(SOAPAction);
  (*tmp)->xml = maybeStrdup(body);
  if ((*tmp)->xml) {
    if (!((*tmp)->doc = xmlParseDoc((xmlChar*)((*tmp)->xml)))) {
      fprintf(stderr, "Parse error for timestamp %s, body [%s]\n", (*tmp)->timestamp, (*tmp)->xml);
    }
  }
  (*tmp)->next = NULL;
}

typedef struct linelist_s {
  char *line;
  struct linelist_s *next;
} *linelist;

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

char *findstatus(linelist l) {
  char *s = (char *)malloc(BUFSIZE);
  if (!strncmp(l->line, "HTTP/1.1 ", 9)) {
    if (sscanf(l->line + 9, "%s", s) == 1) {
      return s;
    }
  }
  return NULL;
}

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

/*
 * Note: This is NOT the worst function I've ever written.
 */
int parseLogFile(char *filename, logInfo *log) {
  FILE *infile = fopen(filename, "r");
  message msg, newmsg;
  char *body;

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

      // Check if this is supposed to be an Expect: 100-continue situation
      char *expect = findheader(msg->lines, "Expect");
      // Handle 100-continue
      if (expect && !strcasecmp(expect, "100-continue")) {
	// fprintf(stderr, "Continuation\n");
	message response = readonemessage(infile);
	message continuation = NULL;
	// If the response message actually is a response from the server, check what it is
	if (response->dir == '<') {
	  char *status = findstatus(response->lines);
	  if (!status) {
	    // If this is a response from the server but it doesn't contain a status code at all, something is wrong
	    fprintf(stderr, "Fatal error: Expect: 100-continue, but response does not contain a status code\n");
	    return 0;
	  } else if (strcmp(status, "100") != 0) {
	    // If there is a status code but it's not "100", this might actually be a direct response - if so, the original
	    // probably contained a request body. We'll just save this response until the next round.
	    // newmsg is supposed to be NULL unless this occurs.
	    // fprintf(stderr, "Server responded with a result, so presumably the client already sent the request\n");
	    newmsg=response;
	    response = NULL;
	  } else {
	    // If it is a "100" response, we can discard it and read a new package.
	    freelinelist(&(response->lines));
	    free(response);
	    continuation = readonemessage(infile);
	  }
	} else {
	  // fprintf(stderr, "Client sent the request body without waiting for a continuation response from server.\n");
	  continuation = response; // Weird case when client doesn't receive 100-continue but continues anyway
	  message response = readonemessage(infile);
	  // If the response message actually is a response from the server, check what it is
	  if (response->dir == '<') {
	    char *status = findstatus(response->lines);
	    if (!status) {
	      // If this is a response from the server but it doesn't contain a status code at all, something is wrong
	      fprintf(stderr, "Fatal error: Expect: 100-continue, but response does not contain a status code\n");
	      return 0;
	    } else if (strcmp(status, "100") != 0) {
	      // If there is a status code but it's not "100", this might actually be a direct response - if so, the original
	      // probably contained a request body. We'll just save this response until the next round.
	      // newmsg is supposed to be NULL unless this occurs.
	      // fprintf(stderr, "Server responded with a result, so presumably the client already sent the request\n");
	      newmsg=response;
	      response = NULL;
	    } else {
	      // If it is a "100" response, we can discard it and read a new package.
	      freelinelist(&(response->lines));
	      free(response);
	      //	    continuation = readonemessage(infile);
	    }
	  }
	}
	if (continuation) {
	  //fprintf(stderr, "Handling continuation packet\n");
	  if (continuation->dir != '>') {
	    fprintf(stderr, "Fatal error: No continuation after 100-continue\n");
	    return 0;
	  }
	  char *act = findheader(continuation->lines, "SOAPAction");
	  if (act != NULL) {
	    fprintf(stderr, "Fatal error: Expected continuation, got new SOAPAction\n");
	    return 0;
	  }
	  //fprintf(stderr, "Adding lines from continuation packet\n");
	  linelist tmp=continuation->lines;
	  addline(&(msg->lines), "");
	  while (tmp) {	
	    addline(&(msg->lines), tmp->line);
	    tmp = tmp->next;
	  }
	  freelinelist(&(continuation->lines));
	  free(continuation);
	} else {
	  //fprintf(stderr, "No continuation to handle\n");
	}
      }

      body = extractbody(msg->lines);

      // If we have already picked up a message from the server, there's no need to try to merge
      // additional segments.
      if (!newmsg) {
	// fprintf(stderr, "Handling any continuation packets in the same direction\n");
	while ((newmsg = readonemessage(infile)) != NULL && newmsg->dir == msg->dir) {
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
	}
      } else {
	//fprintf(stderr, "We already have a saved response message, so no merging of additional request messages\n");
      }

      // printf("Request: %s %s\n[%s]\n", msg->timestamp, SOAPAction, body);
      addlogentry(log, msg->timestamp, NULL, msg->dir, NULL, SOAPAction, body);
      //      fprintf(stderr, "Ready, cleaning up\n");
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
      addlogentry(log, msg->timestamp, NULL, msg->dir, status, NULL, body);
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

/**
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


int main(int argc, char *argv[]) {
  // initialize stuff
  static char filename[BUFSIZE], inbuf[BUFSIZE];
  LIBXML_TEST_VERSION;
  logInfo log=NULL;
  int o;
  char *groupBy=NULL;
  char *nslist=NULL;
  char *outfilename = NULL;
  char *tmpfilename = NULL;
  FILE *outfile = stdout;
  int failed=0;
  
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

  for (int i=optind; i < argc; i++) {
    if (!parseLogFile(argv[i], &log)) {
      failed=1;
      break;
    }
  }

  if (!failed) {
    logInfo tmp = log;
    char *currentTransactionId = NULL;
    char *lastTransactionId = NULL;
    while (tmp) {
      if (tmp->direction == '>') {
	if (tmp->doc && groupBy) {
	  xmlXPathContextPtr context = xmlXPathNewContext(tmp->doc);
	  if (nslist) {
	    register_namespaces(context, (xmlChar *)nslist);
	  }
	  xmlXPathObjectPtr result = xmlXPathEvalExpression((xmlChar *)groupBy, context);
	  
	  if (result) {
	    if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
	      xmlXPathFreeObject(result);
	      printf("No result\n");
	    } else {
	      xmlChar *value = xmlNodeListGetString(tmp->doc, result->nodesetval->nodeTab[0]->xmlChildrenNode, 1);
	      tmp->transactionId = strdup((char *)value);
	      currentTransactionId = tmp->transactionId;
	      xmlFree(value);
	    }
	  }
	}
      } else {
	if (currentTransactionId) {
	  tmp->transactionId = strdup(currentTransactionId);
	}
      }
      if (currentTransactionId && (!lastTransactionId || strcmp(lastTransactionId, currentTransactionId))) {
	// printf("############## New transaction %s\n", currentTransactionId);
	lastTransactionId = currentTransactionId;
	if (outfile) {
	  fclose(outfile);
	}
	snprintf(filename, sizeof(filename), "%s_%s_%s", outfilename, tmp->timestamp, currentTransactionId);
	filename[sizeof(filename)-1] = '\0';
	if (!(outfile=fopen(filename, "w"))) {
	  perror(filename);
	}
      }
      if (outfile) {
	fprintf(outfile, "## %s %s (%s)\n", tmp->timestamp, (tmp->direction=='>')?"request":"response", (tmp->direction=='>')?(tmp->operation):(tmp->status));
	xmlKeepBlanksDefault(0);
	xmlLineNumbersDefault(1);
	xmlThrDefIndentTreeOutput(1);
	xmlSaveFormatFileEnc(tmpfilename, tmp->doc, "utf-8", 1);
	FILE *tmpfile = fopen(tmpfilename, "r");
	size_t n;
	while ((n = fread(inbuf, 1, sizeof(inbuf), tmpfile)) != 0) {
	  fwrite(inbuf, 1, n, outfile);
	}
	fclose(tmpfile);
	fprintf(outfile, "\n");
      }
      tmp = tmp->next;
    }
  }

  if (outfile) {
    fclose(outfile);
  }
  xmlCleanupParser();
  xmlMemoryDump();
  return(0);
}
