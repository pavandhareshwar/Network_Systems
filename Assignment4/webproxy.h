//
//  webproxy.h
//  webProxy
//
//  Created by Pavan Dhareshwar on 11/18/17.
//  Copyright © 2017 Pavan Dhareshwar. All rights reserved.
//

#ifndef webproxy_h
#define webproxy_h

#define LISTEN_SYSCALL_BACKLOG          (10)     /* Max length of pending connections queued up by the kernel */
#define HTTP_REQ_MSG_MAX_LEN            (1024)  /* Max length of an HTTP request message */
//#define PRINT_DEBUG_MESSAGES            (1)
#define TRANSFER_SIZE                   (1024)

#define HTTP_RSP_SP                     " "
#define HTTP_RSP_CRLF                   "\r\n"
#define HTTP_RSP_LFLF                   "\n\n"
#define HTTP_RSP_LF                     "\n"

#define min(a,b)                        (((a) < (b)) ? (a) : (b))

#ifdef PRINT_DEBUG_MESSAGES
#define PRINT_DEBUG_MESSAGE(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( false )
#else
#define PRINT_DEBUG_MESSAGE(...) do{ } while ( false )
#endif


typedef struct _http_req_msg_params_
{
    char    httpReqMethod[10]; /* Extract the HTTP request method in here */
    char    httpReqUri[256]; /* Extract the HTTP request URI in here */
    char    httpReqVersion[50]; /* Extract the HTTP request version in here */
}http_req_msg_params;

typedef struct _proxy_http_req_msg_params_
{
    http_req_msg_params clientHttpReqMsgParams;
    char                hostName[100];
}proxy_http_req_msg_params;

/* HTTP reponse and header */

/* HTTP response body indicating that the we didn't understand the request.  */

static char* badRequestResponseBody =
"\n"
"<html>\n"
" <body>\n"
"  <h1>Bad Request</h1>\n"
"  <p>This server did not understand your request.</p>\n"
" </body>\n"
"</html>\n";

/* HTTP response body indicating that the requested document was not found.  */

static char* notFoundResponseBody =
"\n"
"<html>\n"
" <head>\n"
" <title>404 Not Found</title>\n"
" </head>\n"
" <body>\n"
" <h1>Not Found</h1>\n"
" <p>The requested URL was not found on this server.</p>\n"
" </body>\n"
"</html>\n";

/* HTTP response body indicating that the method was not understood.  */

static char* notImplementedResponseBody =
"\n"
"<html>\n"
" <body>\n"
"  <h1>Method Not Implemented</h1>\n"
"  <p>The method is not implemented by this server.</p>\n"
" </body>\n"
"</html>\n";

static char* internalServerErrorResponseBody =
"\n"
"<html>\n"
" <head>\n"
" <title>500 Internal Server Error</title>\n"
" </head>\n"
"</html>\n";


/* Function prototypes */
static int handleConnRequest(int connId, char *httpReqMsgBuffer);
static void extractAndCheckHttpReqMsgParams(int connId, char *reqLineToken,
                                            http_req_msg_params *clientHttpReqMsgParams, bool *isValid);
static void resolveHostNameToIpAddr(char *hostName, bool *validHostName);
static void extractAndValidateHostName(char *httpReqMsgBuffer, bool *validHostName, char *hostName);

static int handleGetRequest(int connId, http_req_msg_params clientHttpReqMsgParams, char *hostName);
static void sendBadRequestResponse(int connId, http_req_msg_params *clientHttpReqMsgParams);
static void sendNotImplementedResponse(int connId, http_req_msg_params *clientHttpReqMsgParams);
static void sendInternalServerErrorResponse(int connId);
static void sendFileNotFoundResponse(int connId, http_req_msg_params clientHttpReqMsgParams);
static void composeHttpReqMsg(proxy_http_req_msg_params proxyHttpReqMsgParams, char *proxyReqToServer);
static int sendHttpReqMsgToServer(int connId, http_req_msg_params clientHttpReqMsgParams, char *hostName);
static void checkIfCachedCopyExists(char *reqUrl, char *hostName, int *cachedCopyExists);
static void checkIfDirAndFileExists(char *folderName, char *fileName, bool *found);
static void checkIfDirectoryExists(char *dirName);
static int sendCachedCopyToClient(int connId, http_req_msg_params clientHttpReqMsgParams, char *hostName);

#endif /* webproxy_h */
