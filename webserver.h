#ifndef _WEBSERVER_H_
#define _WEBSERVER_H_

typedef struct _ws_conf_params_
{
    int     serverPortNum;              /* server port */
    char    serverDocumentRoot[256];    /* document root */
    int     serverKeepAliveTime;        /* Keep Alive Time */
}ws_conf_params;

typedef struct _http_req_msg_params_
{
    char    httpReqMethod[10]; /* Extract the HTTP request method in here */
    char    httpReqUri[256]; /* Extract the HTTP request URI in here */
    char    httpReqVersion[50]; /* Extract the HTTP request version in here */
}http_req_msg_params;

/* HTTP reponse and header */

/* HTTP response body indicating that the we didn't understand the request.  */

static char* bad_request_response_body =
  "\n"
  "<html>\n"
  " <body>\n"
  "  <h1>Bad Request</h1>\n"
  "  <p>This server did not understand your request.</p>\n"
  " </body>\n"
  "</html>\n";

/* HTTP response body indicating that the requested document was not found.  */

static char* not_found_response_body =
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

static char* bad_method_response_template =
  "HTTP/1.0 501 Method Not Implemented\n"
  "Content-type: text/html\n"
  "\n"
  "<html>\n"
  " <body>\n"
  "  <h1>Method Not Implemented</h1>\n"
  "  <p>The method is not implemented by this server.</p>\n"
  " </body>\n"
  "</html>\n";

#endif // #ifndef _WEBSERVER_H_
