#ifndef _WEBSERVER_H_
#define _WEBSERVER_H_

/*  ----------------------------------------------------------------
     Macros
    ----------------------------------------------------------------
 */

#define LISTEN_SYSCALL_BACKLOG          (10)     /* Max length of pending connections queued up by the kernel */
#define HTTP_REQ_MSG_MAX_LEN            (1024)  /* Max length of an HTTP request message */
//#define PRINT_DEBUG_MESSAGES            (1)
#define TRANSFER_SIZE                   (1024)

//#define HTTP_SEND_ONLY_STATUSLINE     (1)

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

#define ENABLE_PIPELINING               (1)

/*  ----------------------------------------------------------------
     Structure/Enumerations
    ----------------------------------------------------------------
 */
typedef struct _ws_conf_params_
{
    int     serverPortNum;                      /* server port */
    char    serverDocumentRoot[256];            /* document root */
    int     serverKeepAliveTime;                /* Keep Alive Time */
    char    serverIndexFiles[100];              /* Possible index files */
    char    serverSupportedExtensions[20][100];  /* Supported extensions */
    char    serverSupportedFileTypes[20][100];  /* Supported file types */
}ws_conf_params;

typedef struct _http_req_msg_params_
{
    char    httpReqMethod[10]; /* Extract the HTTP request method in here */
    char    httpReqUri[256]; /* Extract the HTTP request URI in here */
    char    httpReqVersion[50]; /* Extract the HTTP request version in here */
}http_req_msg_params;

int extensionCount = 0;

/*  ----------------------------------------------------------------
     Function Prototypes
    ----------------------------------------------------------------
 */

//static int handleConnRequest(int connId, bool *connKeepAlive);
static int handleConnRequest(int connId, char *httpReqMsgBuffer);
static int handleGetRequest(int connId, http_req_msg_params clientHttpReqMsgParams);
static int handlePostRequest(int connId, http_req_msg_params clientHttpReqMsgParams, char *httpReqMsgBuffer);
static int getServerConfigParams(ws_conf_params *serverConfigParams);
static void extractAndCheckHttpReqMsgParams(int connId, char *reqLineToken, http_req_msg_params *clientHttpReqMsgParams, bool *isValid);
static void findIndexFileToUse(char *path, int connId, http_req_msg_params clientHttpReqMsgParams);
static void getContentType(char *fileName, char *contentType);
static void sendBadRequestResponse(int connId, http_req_msg_params *clientHttpReqMsgParams);
static void sendNotImplementedResponse(int connId, http_req_msg_params *clientHttpReqMsgParams);
static void sendInternalServerErrorResponse(int connId);
static void sendFileNotFoundResponse(int connId, http_req_msg_params clientHttpReqMsgParams);
static void parseHttpReqMsgForConnField(int connId, char *httpReqMsgBuffer,
                                        bool *connKeepAlive);
static int calculateTimeElapsedinSecs(struct timespec start, struct timespec *now);
void signalHandler(int sig);
void signalForChildHandler(int sig);

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

static char* postRequestBody =
    "<h1>Post Data</h1>\n"
    "<pre>%s</pre>\n"
    "<div id=\"clear\"></div>\n";

#endif // #ifndef _WEBSERVER_H_
