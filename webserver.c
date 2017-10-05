/* Main code for the webserver */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <unistd.h>     //write
#include <pthread.h>    // thread functions
#include <errno.h>
#include <fcntl.h>

#include "webserver.h"

#define LISTEN_SYSCALL_BACKLOG      (5)     /* Max length of pending connections queued up by the kernel */
#define HTTP_REQ_MSG_MAX_LEN        (1024)  /* Max length of an HTTP request message */
#define PRINT_DEBUG_MESSAGES        (1)
#define TRANSFER_SIZE               (1024)

//#define HTTP_SEND_ONLY_STATUSLINE   (1)

#define HTTP_RSP_SP                 " "
#define HTTP_RSP_CRLF               "\n\n"
#define HTTP_RSP_LF                 "\n"

char serverDefaultDocRoot[] = "/Users/pavandhareshwar/Sites/www";
ws_conf_params serverConfigParams;
static int childProcessCount = 0;

static void handleConnRequest(int connId, bool *connKeepAlive);
static void handleGetRequest(int connId, http_req_msg_params clientHttpReqMsgParams);
static int fillServerConfigParams(ws_conf_params *serverConfigParams);
static void getContentType(char *fileName, char *contentType);
static void getContentLength(char *fileName, int *contentLength);
static void sendBadRequestResponse(int connId, http_req_msg_params clientHttpReqMsgParams);

int main(int argc, char const *argv[])
{
    /*  sockaddr_in structure for socket information about client and server */
    struct sockaddr_in serverSockAddr;
    /*  Server socket */
    int serverSock = -1;

    /*  Create a TCP server socket */
    serverSock = socket(AF_INET, /* socket_family = IPv4 */
                        SOCK_STREAM, /* socket_type = TCP */
                        0 /* Single protocol */);

    if (-1 == serverSock)
    {
        printf("Server socket creation failed\n");
        exit(1);
    }
    else
    {
        printf("Server socket successfully created\n");
    }

    /* Read the ws.conf file to get all the server initialization parameters */
    ws_conf_params serverDefaultConfigParams;

    /*  Define the default server configuration params that will be used if
        there is any error in reading configuration file
    */
    serverDefaultConfigParams.serverPortNum = 8888;
    strcpy((char *)serverDefaultConfigParams.serverDocumentRoot, serverDefaultDocRoot);
    serverDefaultConfigParams.serverKeepAliveTime = 0;

    memset(&serverConfigParams, 0, sizeof(ws_conf_params));

    int retVal = fillServerConfigParams(&serverConfigParams);
    if (retVal != 0)
    {
        printf("Server config file read failed\n");
        printf("Using default configuration\n");
        memcpy(&serverConfigParams, &serverDefaultConfigParams, sizeof(ws_conf_params));
    }
    size_t len = strlen(serverConfigParams.serverDocumentRoot);
    if (len > 0 && serverConfigParams.serverDocumentRoot[len-1] == '\n')
        serverConfigParams.serverDocumentRoot[--len] = '\0';

    //if (printTheseMessages)
    {
        printf("Server configuration : \n");
        printf("Port : %d\n", serverConfigParams.serverPortNum);
        printf("Document Root : %s\n", serverConfigParams.serverDocumentRoot);
        printf("Keep-Alive Time : %d\n", serverConfigParams.serverKeepAliveTime);
    }

    memset(&serverSockAddr, 0, sizeof(serverSockAddr));

    /*  Define sockaddr_in structure for server */
    serverSockAddr.sin_family = AF_INET;    /* socket_family = IPv4 */
    serverSockAddr.sin_port = htons(serverConfigParams.serverPortNum);  /* port, use HTTP port : 80 */
    serverSockAddr.sin_addr.s_addr = INADDR_ANY; /* Receive packets destined to any of the available interfaces */

    /*  Bind (Associate the server socket created with the port number and the
        IP address */
    if (bind(serverSock, /* socket descriptor */
        (struct sockaddr *)&serverSockAddr, /* socket address structure */
        sizeof(serverSockAddr) /* addrlen */) < 0)
    {
        printf("Bind failed\n");
        exit(1);
    }
    else
    {
        printf("Bind successful\n");
    }

    /*  Listen for incoming connections on the server socket */
    /*  The server is blocked until it gets a connection request on the socket */
    listen(serverSock, /* socket descriptor */
            LISTEN_SYSCALL_BACKLOG /* maximum pending connection queued up */);

    printf("Waiting for incoming connections...\n");

    /* Server runs in an infinite loop listening for connections on its socket */
    while (1)
    {
        /* Client address structure */
        struct sockaddr_in clientSockAddr;
        /* Client socket */
        int clientSock = -1;
        socklen_t clientAddrLen = -1;
        bool connKeepAlive = false;
        pid_t child_pid;

        clientAddrLen = sizeof(clientSockAddr);
        /* Accept an incoming connection */
        clientSock = accept(serverSock, /* socket descriptor */
                            (struct sockaddr *)&clientSockAddr, /* sockaddr structure */
                            (socklen_t *)&clientAddrLen /* addrlen */);
        if (clientSock < 0)
        {
            printf("Accept failed\n");
            exit(1);
        }

        /*  Using the multiprocess approach here -
            Creating a new process for every accepted connection */
        child_pid = fork();

        if (child_pid == 0)
        {
            childProcessCount++;
            //printf("Spawned child processes [%d]\n", childProcessCount);
            /* Child process */
            close(serverSock);
            /* Handle the request from the accepted connection */
            handleConnRequest(clientSock, &connKeepAlive);

            /* Persistent Connection*/
            /*  Once the request has been handled and the response has been sent,
                we have to check if the parameter 'connKeepAlive' from handleConnRequest
                function is true (this means there is a 'Connection: Keep Alive'
                in the HTTP request message from the client */
            //if (!connKeepAlive)
            {
                /* Close the connection */
                close(clientSock);
                /* Kill the child process */
                //printf("Killed child processes [%d]\n", childProcessCount--);
                exit(0);
            }
            //else
            //{
            //    printf("connKeepAlive is set. Not closing the clientSock\n");
            //}
        }
        else if (child_pid > 0)
        {
            /* Parent process */
            close(clientSock);
        }
        else
        {
            printf("fork failed, %s\n", strerror(errno));
        }
    }

  return 0;
}

static int fillServerConfigParams(ws_conf_params *serverConfigParams)
{
    //FILE *fp = fopen("/Users/pavandhareshwar/UC_Boulder/2-1/Network Systems/Assignments/Assignment2/Codes/webserver/ws.conf", "r");
    FILE *fp = fopen("ws.conf", "r");
    int retVal = -1;

    char *buffer;
    size_t numBytes = 120;
    char spaceDelimiter[] = " ";
    char colonDelimiter[] = ":";
    ssize_t bytesRead;
    system("pwd");

    buffer = (char *)malloc(numBytes*sizeof(char));

    if (fp)
    {
        while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
        {
            char *token;
            token = strtok(buffer, spaceDelimiter);

            if (strcmp(token, "Listen") == 0)
            {
                token = strtok(NULL, spaceDelimiter);
                serverConfigParams->serverPortNum = atoi(token);
            }
            else if (strcmp(token, "DocumentRoot") == 0)
            {
                token = strtok(NULL, spaceDelimiter);
                strcpy(serverConfigParams->serverDocumentRoot, token);
            }
            else if (strcmp(token, "Keep-Alive") == 0)
            {
                printf("token : %s\n", token);
                token = strtok(NULL, colonDelimiter);
                char *token2 = strtok(token, "=");
                if (strcmp(token2, "timeout") == 0)
                {
                    token2 = strtok(NULL, "=");
                    serverConfigParams->serverKeepAliveTime = atoi(token2);
                }
            }
            else
            {
                /* Do Nothing */
            }
        }

        retVal = 0;
        fclose(fp);
    }

    return retVal;
}

static void handleConnRequest(int connId, bool *connKeepAlive)
{
    char httpReqMsgBuffer[HTTP_REQ_MSG_MAX_LEN]; /* */
    ssize_t bytes_read = -1; /* Bytes successfully read */

    /*  TODO : Add error handling
        The following error codes need to be handled
        400     -- Bad Request
        404     -- Not Found
        501     -- Not Implemented (Requested filetype isn't supported by server)
        500     -- Internal Server Error (Client is fine, can retry)
    */
    bytes_read = read(connId, /* read file descriptor*/
                    httpReqMsgBuffer, /* buffer */
                    (sizeof(httpReqMsgBuffer)-1) /* size of buffer */);
    if (bytes_read > 0)
    {
        http_req_msg_params clientHttpReqMsgParams;

        memset(&clientHttpReqMsgParams, 0, sizeof(clientHttpReqMsgParams));

        /*  Read partial or complete data from the socket successfully */
        /*  NULL terminate the socket read buffer */
        httpReqMsgBuffer[bytes_read] = '\0';

        /*  The client sends an HTTP request of the form
            Example format taken from the internet
            GET /index.html HTTP/1.1
            User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
            Host: localhost
            Accept-Language: en-us
            Accept-Encoding: gzip, deflate
            Connection: Keep-Alive

            GET         -- HTTP request method. Others are POST, HEAD etc
            index.html  -- HTTP request URI
            HTTP/1.1    -- HTTP request version
            User-Agent  -- Info about the user-agent originating the request.
            Host        -- The domain name of the server (and the TCP port on which the server is listening)
            Connection  -- Control options for the current connection.
        */
        /*  The first line of the client's HTTP request will be of the
            form above containing the request method, URI and version
        */
        printf("HTTP request message :\n");
        printf("%s\n", httpReqMsgBuffer);
        sscanf(httpReqMsgBuffer, "%s %s %s", clientHttpReqMsgParams.httpReqMethod,
               clientHttpReqMsgParams.httpReqUri, clientHttpReqMsgParams.httpReqVersion);

#if 0
        if (printTheseMessages)
        {
            printf("HTTP Request Parameters: \n");
            printf("HTTP Request Method : %s\n", clientHttpReqMsgparams.httpReqMethod);
            printf("HTTP Request URI : %s\n", clientHttpReqMsgparams.httpReqUri);
            printf("HTTP Request Version : %s\n", clientHttpReqMsgparams.httpReqVersion);
        }
#endif

#if 1
        /*  TODO : parse the http request message for 'Connection' field and
            if it says 'Keep-Alive', then the server should keep the connection
            open for 'Keep-Alive time' specified in the ws.conf file.
        */
        /*  We have to continue reading until we get '\r\n\r\n' (HTTP specifies
            CR/LF as the line delimiter.
        */

        char httpReqMsgBufferCopy[HTTP_REQ_MSG_MAX_LEN];
        strcpy(httpReqMsgBufferCopy, httpReqMsgBuffer);

        char *token = strtok(httpReqMsgBuffer, "\r\n");
        while (token != NULL)
        {
            //printf("Token : %s\n", token);
            token = strtok(NULL, "\r\n");

            char *subStr = NULL;
            if ((subStr = strstr(token, "Connection")) != NULL)
            {
                //printf("subStr : %s\n", subStr);
                char *token2 = strtok(subStr, ":");
                token2 = strtok(NULL, ":");
                //printf("Connection Field : %s\n", token2);
                if (false == *connKeepAlive)
                {
                    *connKeepAlive = true;
                }
                break;
            }
        }

        char *tok = strtok(httpReqMsgBufferCopy, "\r\n");
        while (tok != NULL)
        {
            tok = strtok(NULL, "\r\n");

            char *subStr = NULL;
            if ((subStr = strstr(tok, "Accept:")) != NULL)
            {
                //printf("subStr : %s\n", subStr);
                break;
            }
        }
        printf("--------------------------\n");
#else
        while (strstr (httpReqMsgBuffer, "\r\n\r\n") == NULL)
            bytes_read = read(connId, httpReqMsgBuffer, sizeof(httpReqMsgBuffer));
#endif

        /* Check the HTTP request params extracted to check for incompetencies */
        if ((strcmp(clientHttpReqMsgParams.httpReqVersion, "HTTP/1.0") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqVersion, "HTTP/1.1") != 0))
        {
            /*  The webserver supports only HTTP request version 1.0 and 1.1
                Sending an HTTP response with unsupported HTTP request version
            */
            printf("HTTP version not supported\n");
            sendBadRequestResponse(connId, clientHttpReqMsgParams);
        }

        if ((strcmp(clientHttpReqMsgParams.httpReqMethod, "GET") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqMethod, "POST") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqMethod, "HEAD") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqMethod, "PUT") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqMethod, "DELETE") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqMethod, "CONNECT") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqMethod, "OPTIONS") != 0) &&
            (strcmp(clientHttpReqMsgParams.httpReqMethod, "TRACE") != 0))
        {
            /*  The webserver supports only GET method. Sending an HTTP response
                with unsupported HTTP request method
            */
            printf("HTTP method not supported\n");
            sendBadRequestResponse(connId, clientHttpReqMsgParams);
        }

        if (strcmp(clientHttpReqMsgParams.httpReqMethod, "GET") == 0)
        {
            /* Handle GET request */
            handleGetRequest(connId, clientHttpReqMsgParams);
        }
    }
    else if (bytes_read == 0)
    {
        printf("HTTP request message read from socket failed\n");
    }
    else
    {
        /* read system call failed */
        printf("Read system call failed, %s\n", strerror(errno));
    }
}

static void handleGetRequest(int connId, http_req_msg_params clientHttpReqMsgParams)
{
    /*  Process the HTTP GET request and send appropriate response back to
        the client
    */
    char path[512];
    char dataBuffer[TRANSFER_SIZE];
    int fileDesc = -1;
    ssize_t bytes_read = -1;
    bool isFileIndexHtml = false;

    memset(path, '\0', sizeof(path));
    if (strcmp(clientHttpReqMsgParams.httpReqUri, "/") == 0)
    {
        /*  No file is requested in the URL (just the directory is requested),
            so the default page (index.html or index.htm) is found and sent
            as reponse to the client.
            TODO : The default web page and document root directory should be
            searched in the server configuration file.
        */
        //sprintf(path, "%s%c%s", "/Users/pavandhareshwar/Sites/www", '/', "index.html");
        sprintf(path, "%s%s", (char *)serverConfigParams.serverDocumentRoot, "/index.html");
        isFileIndexHtml = true;
    }
    else
    {
        //printf ("Request Uri : %s\n", clientHttpReqMsgParams.httpReqUri);
        //sprintf(path, "%s%c%s", "/Users/pavandhareshwar/Sites/www", '/', file);
        sprintf(path, "%s%s", (char *)serverConfigParams.serverDocumentRoot, clientHttpReqMsgParams.httpReqUri);
        isFileIndexHtml = false;
    }

    //printf("Path : %s\n", path);
    /*  TODO : The HTTP response has the following lines
        Status-Line : HTTP-Version SP Status-Code SP Reason-Phrase CRLF
            Example : HTTP/1.1 200 OK

            The following status codes are used in the HTTP response:
            200     - OK
            400     - Bad Request
            404     - Not Found
            500     - Internal Server Error
            501     - Not Implemented

        Content-Type: <> #Tells about the type of content and the formatting of <file contents>
        Content-Length: <> #Numeric length value of the no. of bytes of <file contents>
        Connection: Keep-alive/Close
        <file contents>
    */
    if ((fileDesc = open(path, O_RDONLY)) != -1 )
	{
        //send(connId, "HTTP/1.0 200 OK\n\n", 17, 0);
        if (true == isFileIndexHtml)
        {
            printf("Sending index file contents : %s\n", path);
            /* Status-Line */
            char statusLine[100];
            sprintf(statusLine, "%s%s%d%s%s%s", clientHttpReqMsgParams.httpReqVersion,
                    HTTP_RSP_SP, 200, HTTP_RSP_SP, "OK", HTTP_RSP_CRLF);
            send(connId, statusLine, strlen(statusLine), 0);

            /* File Contents */
    		while ( (bytes_read=read(fileDesc, dataBuffer, TRANSFER_SIZE))>0 )
    			write(connId, dataBuffer, bytes_read);

            printf("Sent index file contents\n");
        }
        else
        {
            printf("Sending requested file contents : %s\n", path);
            /* Status-Line */
            char statusLine[100];
#if defined(HTTP_SEND_ONLY_STATUSLINE)
            sprintf(statusLine, "%s%s%d%s%s%s", clientHttpReqMsgParams.httpReqVersion,
                    HTTP_RSP_SP, 200, HTTP_RSP_SP, "OK", HTTP_RSP_CRLF);
#else
            sprintf(statusLine, "%s%s%d%s%s%s", clientHttpReqMsgParams.httpReqVersion,
                    HTTP_RSP_SP, 200, HTTP_RSP_SP, "OK", HTTP_RSP_LF);
#endif
            send(connId, statusLine, strlen(statusLine), 0);

            /* Content-Type */
            char contentType[100];
            getContentType(clientHttpReqMsgParams.httpReqUri, contentType);
            //printf("Content-Type : %s for file : %s\n", contentType, clientHttpReqMsgParams.httpReqUri);
            char contentTypeHeaderField[100];
            //sprintf(contentTypeHeaderField, "%s%s%s%s", "Content-Type", ":"
            //        HTTP_RSP_SP, contentType, HTTP_RSP_CRLF);
            sprintf(contentTypeHeaderField, "%s%s%s%s", "Content-Type", ":"
                    HTTP_RSP_SP, contentType, HTTP_RSP_LF);
            //printf("content type field(%s), length : %lu\n", contentTypeHeaderField, strlen(contentTypeHeaderField));
#if !defined(HTTP_SEND_ONLY_STATUSLINE)
            send(connId, contentTypeHeaderField, strlen(contentTypeHeaderField), 0);
#endif

            /* Content-Length */
            off_t contentLength = lseek(fileDesc, 0, SEEK_END);
            lseek(fileDesc, 0, SEEK_SET);
            //printf("Content-Legth : %d for file : %s\n", (int)contentLength, clientHttpReqMsgParams.httpReqUri);
            char contentLengthHeaderField[100];
            sprintf(contentLengthHeaderField, "%s%s%d%s", "Content-Length", ":"
                    HTTP_RSP_SP, (int)contentLength, HTTP_RSP_CRLF);
            //printf("content length field(%s), length : %lu\n", contentLengthHeaderField, strlen(contentLengthHeaderField));
#if !defined(HTTP_SEND_ONLY_STATUSLINE)
            send(connId, contentLengthHeaderField, strlen(contentLengthHeaderField), 0);
#endif

            /* File Contents */
    		while ((bytes_read=read(fileDesc, dataBuffer, TRANSFER_SIZE)) > 0)
    			write(connId, dataBuffer, bytes_read);

            printf("Sent requested file contents\n");
        }
	}
	else
    {
        printf("File %s not found\n", path);
        char notFoundHttpResponse[1024];
        char *pNotFoundHttpResponse = &notFoundHttpResponse[0];
        
        //send(connId, "HTTP/1.0 404 Not Found\n\n", 23, 0);
        char statusLine[100];
        sprintf(statusLine, "%s%s%d%s%s%s", clientHttpReqMsgParams.httpReqVersion,
                HTTP_RSP_SP, 404, HTTP_RSP_SP, "Not Found", HTTP_RSP_LF);
        
        strcpy(pNotFoundHttpResponse, statusLine);
        pNotFoundHttpResponse += strlen(statusLine);
        
        char contentTypeHeaderField[100];
        sprintf(contentTypeHeaderField, "%s%s%s%s", "Content-Type", ":"
                HTTP_RSP_SP, "text/html", HTTP_RSP_LF);
        
        strcpy(pNotFoundHttpResponse, contentTypeHeaderField);
        pNotFoundHttpResponse += strlen(contentTypeHeaderField);
        
        strcpy(pNotFoundHttpResponse, not_found_response_body);
        
        //printf("Response : %s\n", notFoundHttpResponse);
        
        send(connId, notFoundHttpResponse, strlen(notFoundHttpResponse), 0);
    }
}

static void getContentType(char *fileName, char *contentType)
{
    int systemCmdRetval = -1;
    
    if (fileName[0] == '/')
    {
        memmove(fileName, fileName+1, strlen(fileName));
    }
    
    char command[100];
    sprintf(command, "file --mime-type %s/%s > out.txt", serverConfigParams.serverDocumentRoot, fileName);
    
    systemCmdRetval = system(command);
    if (-1 != systemCmdRetval)
    {
        printf("System command sucess\n");
        char *buffer = NULL;
        size_t bufferSize = 0;
        ssize_t numBytesRead = 0;
        FILE *fp = fopen("out.txt", "r");
        if (fp)
        {
            if ((numBytesRead = getline(&buffer, &bufferSize, fp)) != -1)
            {
                char *subStr = strstr(buffer, ":");
                
                /* Removing the : and space character at the beginning */
                if (subStr[0] == ':')
                    memmove(subStr, subStr+1, strlen(subStr));
                
                if (subStr[0] == ' ')
                    memmove(subStr, subStr+1, strlen(subStr));
                
                size_t len = strlen(subStr);
                /* Removing the trailing newline character */
                if (len > 0 && subStr[len-1] == '\n')
                    subStr[--len] = '\0';
                //printf("Content-Type : %s\n", subStr);
                strcpy(contentType, subStr);
            }
        }
        
        /* Remove temp file */
        remove("out.txt");
        free(buffer);
        fclose(fp);
    }
}

static void sendBadRequestResponse(int connId, http_req_msg_params clientHttpReqMsgParams)
{
    char badRequestHttpResponse[1024];
    char *pBadRequestHttpResponse = &badRequestHttpResponse[0];
    
    char statusLine[100];
    sprintf(statusLine, "%s%s%d%s%s%s", clientHttpReqMsgParams.httpReqVersion,
            HTTP_RSP_SP, 400, HTTP_RSP_SP, "Bad Request", HTTP_RSP_LF);
    
    strcpy(pBadRequestHttpResponse, statusLine);
    pBadRequestHttpResponse += strlen(statusLine);
    
    char contentTypeHeaderField[100];
    sprintf(contentTypeHeaderField, "%s%s%s%s", "Content-Type", ":"
            HTTP_RSP_SP, "text/html", HTTP_RSP_LF);
    
    strcpy(pBadRequestHttpResponse, contentTypeHeaderField);
    pBadRequestHttpResponse += strlen(contentTypeHeaderField);
    
    strcpy(pBadRequestHttpResponse, bad_request_response_body);
    
    printf("Bad Request Response : %s\n", badRequestHttpResponse);
    
    send(connId, badRequestHttpResponse, strlen(badRequestHttpResponse), 0);
}
