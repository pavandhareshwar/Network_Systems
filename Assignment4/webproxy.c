//
//  webproxy.c
//  webProxy
//
//  Created by Pavan Dhareshwar on 11/18/17.
//  Copyright © 2017 Pavan Dhareshwar. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <unistd.h>     //write
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netdb.h>
#include <dirent.h>

#include "webproxy.h"

int main(int argc, const char * argv[])
{
    /*  Server socket */
    int proxySock = -1;
    
    /* Client socket */
    int clientSock;
    
    /*  sockaddr_in structure for socket information about client and server */
    struct sockaddr_in proxySockAddr;
    char httpReqMsgBuffer[HTTP_REQ_MSG_MAX_LEN];
    
    if (argc < 2)
    {
        printf("Usage: webproxy <port_num>\n");
        exit(1);
    }
    
    int proxyPortNum = atoi(argv[1]);
    
    /*  Define sockaddr_in structure for server */
    proxySockAddr.sin_family = AF_INET;    /* socket_family = IPv4 */
    proxySockAddr.sin_port = htons(proxyPortNum);  /* port */
    inet_pton(AF_INET, "127.0.0.1", &(proxySockAddr.sin_addr)); /* Receive packets destined to any of the available interfaces */
    
    /*  Create a TCP server socket */
    proxySock = socket(AF_INET, /* socket_family = IPv4 */
                        SOCK_STREAM, /* socket_type = TCP */
                        0 /* Single protocol */);
    
    if (-1 == proxySock)
    {
        printf("Web proxy socket creation failed\n");
        exit(1);
    }
    else
    {
        printf("Web proxy socket successfully created\n");
    }
    
    /*  Bind (Associate the server socket created with the port number and the
     IP address */
    if (bind(proxySock, /* socket descriptor */
             (struct sockaddr *)&proxySockAddr, /* socket address structure */
             sizeof(proxySockAddr) /* addrlen */) < 0)
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
    listen(proxySock, /* socket descriptor */
           LISTEN_SYSCALL_BACKLOG /* maximum pending connection queued up */);
    
    printf("Waiting for incoming connections...\n");
    
    while (1)
    {
        /* Client address structure */
        struct sockaddr_in clientSockAddr;
        socklen_t clientAddrLen = -1;
        pid_t child_pid;
        
        clientAddrLen = sizeof(clientSockAddr);
        /* Accept an incoming connection */
        clientSock = accept(proxySock, /* socket descriptor */
                            (struct sockaddr *)&clientSockAddr, /* sockaddr structure */
                            (socklen_t *)&clientAddrLen /* addrlen */);
        if (clientSock < 0)
        {
            printf("Accept failed\n");
            exit(1);
        }
        else
        {
            PRINT_DEBUG_MESSAGE("Accept success, clientSock : %d\n", clientSock);
        }
        
        /*  Using the multiprocess approach here -
         Creating a new process for every accepted connection */
        child_pid = fork();
        
        if (child_pid == 0)
        {
            PRINT_DEBUG_MESSAGE("Created a child process for a new accepted connection, "
                   "PID: %d\n", getpid());
            /* Child process */
            /* Close the parent socket in the child process because we want
             the child process to handle the connection request and not
             listen for any connection requests.
             */
            close(proxySock);
            
            memset(httpReqMsgBuffer, '\0', HTTP_REQ_MSG_MAX_LEN);
            
            int retVal = handleConnRequest(clientSock, httpReqMsgBuffer);
            if (retVal != 0)
            {
                printf("Handle Connection Request Failed\n");
            }
            
            /* Close the client socket */
            PRINT_DEBUG_MESSAGE("Closing client socket: %d\n", clientSock);
            close(clientSock);
            
            /* Kill the child process */
            exit(0);
        }
        else if (child_pid > 0)
        {
            /* Parent process */
            /* We close the child socket here, because we don't want the parent
             process to receive HTTP request message on the client socket
             */
            close(clientSock);
        }
        else
        {
            printf("fork failed, %s\n", strerror(errno));
        }
    }
    
    return 0;
}

static int handleConnRequest(int connId, char *httpReqMsgBuffer)
{
    int retVal = -1;
    bool isHttpReqLineValid = false;
    http_req_msg_params clientHttpReqMsgParams;
    
    memset(&clientHttpReqMsgParams, 0, sizeof(clientHttpReqMsgParams));
    
    ssize_t bytes_read = -1; /* Bytes successfully read */
    bytes_read = read(connId, /* read file descriptor*/
                      httpReqMsgBuffer, /* buffer */
                      (HTTP_REQ_MSG_MAX_LEN-1) /* size of buffer */);
    
    if (bytes_read > 0)
    {
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
        
        PRINT_DEBUG_MESSAGE("\n\nhttpReqMsg: %s\n", httpReqMsgBuffer);
        
        char hostName[100];
        memset(hostName, '\0', sizeof(hostName));
        
        bool validHostName = false;
        extractAndValidateHostName(httpReqMsgBuffer, &validHostName, hostName);
        
        if (validHostName == true)
        {
            char httpReqMsgBufferCopy[HTTP_REQ_MSG_MAX_LEN];
            strcpy(httpReqMsgBufferCopy, httpReqMsgBuffer);
            
            char *reqLineToken = strtok(httpReqMsgBufferCopy, "\r\n");
            if (NULL != reqLineToken)
            {
                memset(&clientHttpReqMsgParams, '\0', sizeof(clientHttpReqMsgParams));
                extractAndCheckHttpReqMsgParams(connId, reqLineToken, &clientHttpReqMsgParams, &isHttpReqLineValid);
                if (isHttpReqLineValid)
                {
                    /*  We have to continue reading until we get '\r\n\r\n' (HTTP specifies
                     CR/LF as the line delimiter.
                     */
                    
                    PRINT_DEBUG_MESSAGE("=======================================\n");
                    PRINT_DEBUG_MESSAGE("HTTP Request Parameters: \n");
                    PRINT_DEBUG_MESSAGE("HTTP Request Method : %s\n", clientHttpReqMsgParams.httpReqMethod);
                    PRINT_DEBUG_MESSAGE("HTTP Request URI : %s\n", clientHttpReqMsgParams.httpReqUri);
                    PRINT_DEBUG_MESSAGE("HTTP Request Version : %s\n", clientHttpReqMsgParams.httpReqVersion);
                    PRINT_DEBUG_MESSAGE("=======================================\n");
                    
                    if (strcmp(clientHttpReqMsgParams.httpReqMethod, "GET") == 0)
                    {
                        /* Handle GET request */
                        retVal = handleGetRequest(connId, clientHttpReqMsgParams, hostName);
                    }
                    else
                    {
                        /* Do Nothing */
                    }
                }
                else
                {
                    printf("HTTP request line invalid\n");
                }
            }
            else
            {
                printf("reqLineToken is NULL\n");
            }
        }
        else
        {
            printf("Hostname Invalid\n");
            sendBadRequestResponse(connId, &clientHttpReqMsgParams);
            retVal = -1;
        }
    }
    else if (bytes_read == 0)
    {
        printf("HTTP request message read from socket failed\n");
        retVal = -1;
    }
    else
    {
        /* read system call failed */
        printf("Read system call failed, %d(%s)\n", errno, strerror(errno));
        retVal = -1;
    }
    
    return retVal;
}

void extractAndValidateHostName(char *httpReqMsgBuffer, bool *validHostName, char *hostName)
{
    char httpReqMsgBufferCopy[HTTP_REQ_MSG_MAX_LEN];
    strcpy(httpReqMsgBufferCopy, httpReqMsgBuffer);
    
    char *token = strtok(httpReqMsgBufferCopy, "\r\n");
    while (token != NULL)
    {
        char *subStr = NULL;
        if ((subStr = strstr(token, "Host")) != NULL)
        {
            char *token2 = strtok(subStr, ":");
            token2 = strtok(NULL, ":");
            
            strcpy(hostName, token2);
            if (*hostName == ' ')
            {
                memcpy(hostName, hostName+1, strlen(hostName));
            }
            PRINT_DEBUG_MESSAGE("HostName: %s\n", hostName);
            
            resolveHostNameToIpAddr(hostName, validHostName);
            
            break;
        }
        token = strtok(NULL, "\r\n");
    }
    return;
}

void extractAndCheckHttpReqMsgParams(int connId, char *reqLineToken,
                                     http_req_msg_params *clientHttpReqMsgParams, bool *isValid)
{
    char spaceDelimiter[] = " ";
    *isValid = true;
    
    /* Extract the HTTP method, URL and version field */
    char *token = strtok(reqLineToken, spaceDelimiter);
    if (token != NULL)
    {
        strcpy(clientHttpReqMsgParams->httpReqMethod, token);
    }
    
    token = strtok(NULL, spaceDelimiter);
    if (token != NULL)
    {
        strcpy(clientHttpReqMsgParams->httpReqUri, token);
    }
    
    token = strtok(NULL, spaceDelimiter);
    if (token != NULL)
    {
        strcpy(clientHttpReqMsgParams->httpReqVersion, token);
    }
    
    /* Check the HTTP request params extracted to check for incompetencies */
    if ((strcmp(clientHttpReqMsgParams->httpReqMethod, "GET") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqMethod, "POST") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqMethod, "HEAD") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqMethod, "PUT") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqMethod, "DELETE") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqMethod, "CONNECT") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqMethod, "OPTIONS") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqMethod, "TRACE") != 0))
    {
        /*  The webserver supports only GET method. Sending an HTTP response
            with unsupported HTTP request method
         */
        printf("HTTP method %s not supported\n", clientHttpReqMsgParams->httpReqMethod);
        sendBadRequestResponse(connId, clientHttpReqMsgParams);
        *isValid = false;
        return;
    }
    
    if ((strcmp(clientHttpReqMsgParams->httpReqVersion, "HTTP/1.0") != 0) &&
        (strcmp(clientHttpReqMsgParams->httpReqVersion, "HTTP/1.1") != 0))
    {
        /*  The webserver supports only HTTP request version 1.0 and 1.1
         Sending an HTTP response with unsupported HTTP request version
         */
        printf("HTTP version %s not supported\n", clientHttpReqMsgParams->httpReqVersion);
        sendBadRequestResponse(connId, clientHttpReqMsgParams);
        *isValid = false;
        return;
    }
    
    /*  This is a scenario where the URL field is missing and the http
     version field gets extracted into the URL field
     */
    if ((strcmp(clientHttpReqMsgParams->httpReqUri, "HTTP/1.0") == 0) ||
        (strcmp(clientHttpReqMsgParams->httpReqUri, "HTTP/1.1") == 0))
    {
        /*  The webserver supports only HTTP request version 1.0 and 1.1
         Sending an HTTP response with unsupported HTTP request version
         */
        printf("HTTP URL field missing\n");
        sendBadRequestResponse(connId, clientHttpReqMsgParams);
        *isValid = false;
        return;
    }
    
    if ((strcmp(clientHttpReqMsgParams->httpReqMethod, "GET") != 0))
    {
        /*  The webserver supports only GET and POST methods. Sending an
         HTTP response with unsupported HTTP request method
         */
        printf("HTTP method %s not implemented\n", clientHttpReqMsgParams->httpReqMethod);
        sendBadRequestResponse(connId, clientHttpReqMsgParams);
        *isValid = false;
        return;
    }
    
    return;
}

void resolveHostNameToIpAddr(char *hostName, bool *validHostName)
{
    struct hostent *hostEnt;
    struct in_addr **addr_list;
    
    if ((hostEnt = gethostbyname(hostName)) == NULL)
    {
        // get the host info
        perror("gethostbyname");
        if (errno == HOST_NOT_FOUND)
        {
            printf("Host not found\n");
            *validHostName = false;
        }
    }
    else
    {
        *validHostName = true;
        
        // print information about this host:
        PRINT_DEBUG_MESSAGE("Official name is: %s\n", hostEnt->h_name);
        PRINT_DEBUG_MESSAGE("IP addresses: ");
        addr_list = (struct in_addr **)hostEnt->h_addr_list;
        for(int i = 0; addr_list[i] != NULL; i++)
        {
            PRINT_DEBUG_MESSAGE("%s\n", inet_ntoa(*addr_list[i]));
        }
    }
}

int handleGetRequest(int connId, http_req_msg_params clientHttpReqMsgParams, char *hostName)
{
    int retVal = -1;
    int cachedCopyExists = 0;
    
    checkIfCachedCopyExists(clientHttpReqMsgParams.httpReqUri, hostName, &cachedCopyExists);
    
    if (cachedCopyExists != -1)
    {
        if (cachedCopyExists == 0)
        {
            sendHttpReqMsgToServer(connId, clientHttpReqMsgParams, hostName);
        }
        else
        {
            printf("Cached copy exists\n");
            sendCachedCopyToClient(connId, clientHttpReqMsgParams, hostName);
            
        }
    }
    
    retVal = 0;
    
    return retVal;
}

void checkIfCachedCopyExists(char *reqUrl, char *hostName, int *cachedCopyExists)
{
    char folderToCheck[100];
    char reqUrlCopy[100];
    char folderName[100];
    char fileName[100];
    
    memset(reqUrlCopy, '\0', sizeof(reqUrlCopy));
    memset(folderToCheck, '\0', sizeof(folderToCheck));
    memset(folderName, '\0', sizeof(folderName));
    memset(fileName, '\0', sizeof(fileName));
    
    strcpy(reqUrlCopy, reqUrl);
    
    char *subStr = strstr(reqUrlCopy, hostName);
    if (subStr)
    {
        memcpy(subStr, subStr+strlen(hostName), strlen(subStr));
        if (*subStr == '/' && *(subStr+1) == '\0')
        {
            strcpy(fileName, "/");
        }
        else
        {
            memcpy(subStr, subStr+1, strlen(subStr));
            strcpy(folderToCheck, subStr);
            
            char folderToCheckCopy[100];
            memset(folderToCheckCopy, '\0', sizeof(folderToCheckCopy));
            
            strcpy(folderToCheckCopy, folderToCheck);
            
            for (int i = (int)strlen(folderToCheckCopy); i > 0; i--)
            {
                if (folderToCheckCopy[i] == '/')
                {
                    char folderNameTemp[100];
                    memset(folderNameTemp, '\0', sizeof(folderToCheckCopy));
                    strncpy(folderNameTemp, folderToCheckCopy, i);
                    sprintf(folderName, "%s/%s", hostName, folderNameTemp);
                    strcpy(fileName, folderToCheckCopy+i+1);
                    break;
                }
            }
        }
    }
    
    printf("reqUrl: %s, folderName: %s, fileName: %s\n", reqUrl, folderName, fileName);
    
    bool found = 0;
    if (*folderName != '\0')
    {
        checkIfDirAndFileExists(folderName, fileName, &found);
        
        if (found == true)
        {
            *cachedCopyExists = 1;
        }
        else
        {
            *cachedCopyExists = 0;
        }
    }
    else
    {
        sprintf(folderName, "%s", hostName);
        checkIfDirAndFileExists(folderName, fileName, &found);
        
        if (found == true)
        {
            *cachedCopyExists = 1;
        }
        else
        {
            *cachedCopyExists = 0;
        }
    }
    
    return;
}

void checkIfDirAndFileExists(char *folderName, char *fileName, bool *found)
{
    char fullFilePath[100];
    memset(fullFilePath, '\0', sizeof(fullFilePath));
    sprintf(fullFilePath, "%s/%s", folderName, fileName);
    
    DIR* dir = opendir(folderName);
    if (dir)
    {
        /* Directory exists. */
        printf("Directory %s exists\n", folderName);
    
        FILE *fp = fopen(fullFilePath, "r");
        if (fp)
        {
            *found = true;
            fclose(fp);
        }
        
        closedir(dir);
    }
    else
    {
        char slashDelimiter[] = "/";
        char folderNameCopy[100];
        memset(folderNameCopy, '\0', sizeof(folderNameCopy));
        
        strcpy(folderNameCopy, folderName);
        
        printf("Directory %s doesn't exist\n", folderName);
        char folderPath[100];
        memset(folderPath, '\0', sizeof(folderPath));
        
        char *token = strtok(folderNameCopy, slashDelimiter);
        while(token)
        {
            strcat(folderPath, token);
            checkIfDirectoryExists(folderPath);
            strcat(folderPath, "/");
            token = strtok(NULL, slashDelimiter);
        }
    }
    return;
}

void checkIfDirectoryExists(char *dirName)
{
    DIR* dir = opendir(dirName);
    if (dir)
    {
        /* Directory exists. */
        PRINT_DEBUG_MESSAGE("Directory %s exists\n", dirName);
        closedir(dir);
    }
    else if (ENOENT == errno)
    {
        /* Directory does not exist. Creating one. */
        mode_t process_mask = umask(0);
        int result_code = mkdir(dirName, S_IRWXU | S_IRWXG | S_IRWXO);
        umask(process_mask);
        if (result_code == 0)
        {
            PRINT_DEBUG_MESSAGE("Directory %s successfully created\n", dirName);
        }
    }
    else
    {
        /* opendir() failed for some other reason. Do nothing */
    }
}

int sendCachedCopyToClient(int connId, http_req_msg_params clientHttpReqMsgParams, char *hostName)
{
    char *fullFilePath = strstr(clientHttpReqMsgParams.httpReqUri, hostName);
    char hostNameWithSlash[100];
    memset(hostNameWithSlash, '\0', sizeof(hostNameWithSlash));
    
    sprintf(hostNameWithSlash, "%s%s", hostName, "/");
    
    if (strcmp(fullFilePath, hostNameWithSlash) == 0)
    {
        sprintf(fullFilePath, "%s%s", fullFilePath, "index.html");
    }
    printf("fullFilePath: %s\n", fullFilePath);
    
    FILE *fpRd = NULL;
    int fileSize = -1;
    fpRd = fopen(fullFilePath, "r");
    if (!fpRd)
    {
        printf("File Open failed\n");
        return -1;
    }
    else
    {
        fseek(fpRd, 0, SEEK_END);
        fileSize = (int)ftell(fpRd);
        fseek(fpRd, 0, SEEK_SET);
    }
    
    char receiveBuffer[10*1024];
    int readSize = 0;
    while (readSize < fileSize)
    {
        int copySize = min(sizeof(receiveBuffer), (fileSize - readSize));
        memset(receiveBuffer, '\0', sizeof(receiveBuffer));
        fread(receiveBuffer, sizeof(char), copySize, fpRd);
        write(connId, receiveBuffer, copySize);
        readSize += copySize;
    }
    
    return 0;
}

int sendHttpReqMsgToServer(int connId, http_req_msg_params clientHttpReqMsgParams, char *hostName)
{
    int retVal = -1;
    struct sockaddr_in serverAddr;
    int serverPort = 80;
    struct hostent *hp;
    
    char *fullFilePath = strstr(clientHttpReqMsgParams.httpReqUri, hostName);
    char hostNameWithSlash[100];
    memset(hostNameWithSlash, '\0', sizeof(hostNameWithSlash));
    
    sprintf(hostNameWithSlash, "%s%s", hostName, "/");
    
    if (strcmp(fullFilePath, hostNameWithSlash) == 0)
    {
        sprintf(fullFilePath, "%s%s", fullFilePath, "index.html");
    }
    //printf("fullFilePath: %s\n", fullFilePath);

    FILE *fpWtr = NULL;
    fpWtr = fopen(fullFilePath, "w");
    if (!fpWtr)
    {
        printf("File Open failed\n");
        return -1;
    }
    
    if((hp = gethostbyname(hostName)) == NULL){
        herror("gethostbyname");
        return -1;
    }
    
    proxy_http_req_msg_params proxyHttpReqMsgParams;
    memset(&proxyHttpReqMsgParams, '\0', sizeof(proxyHttpReqMsgParams));
    
    strcpy(proxyHttpReqMsgParams.hostName, hostName);
    memcpy(&proxyHttpReqMsgParams.clientHttpReqMsgParams, &clientHttpReqMsgParams, sizeof(clientHttpReqMsgParams));
    
    /*  If the proxy server doesn't have the contents requested by the
     client, then it will compose an HTTP request message to the
     webserver and get the contents from the webserver and send it
     to the client as part of the response message. */
    
    char proxyReqToServer[256];
    memset(proxyReqToServer, '\0', sizeof(proxyReqToServer));
    
    composeHttpReqMsg(proxyHttpReqMsgParams, proxyReqToServer);
    
    bcopy(hp->h_addr, &serverAddr.sin_addr, hp->h_length);
    serverAddr.sin_port = htons(serverPort);
    serverAddr.sin_family = AF_INET;
    
    int tcpSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (tcpSocket < 0)
        printf("Error opening socket\n");
    
    if (connect(tcpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
        printf("Error Connecting\n");
    
    if (send(tcpSocket, proxyReqToServer, strlen(proxyReqToServer), 0) < 0)
        printf("Error with send()\n");
    
    char receiveBuffer[10*1024];
    while (recv(tcpSocket, receiveBuffer, sizeof(receiveBuffer) - 1 , 0) != 0)
    {
        fwrite(receiveBuffer, sizeof(char), strlen(receiveBuffer), fpWtr);
        write(connId, receiveBuffer, strlen(receiveBuffer));
        memset(receiveBuffer, '\0', sizeof(receiveBuffer));
    }
    
    close(tcpSocket);
    
    retVal = 0;
    
    return retVal;
}

void composeHttpReqMsg(proxy_http_req_msg_params proxyHttpReqMsgParams, char *proxyReqToServer)
{
    sprintf(proxyReqToServer, "GET %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\n\r\n",
            proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqUri , proxyHttpReqMsgParams.hostName);
    
    PRINT_DEBUG_MESSAGE("GET request to server: %s\n", proxyReqToServer);
    
    return;
}

void sendBadRequestResponse(int connId, http_req_msg_params *clientHttpReqMsgParams)
{
    char badRequestHttpResponse[1024];
    char *pBadRequestHttpResponse = &badRequestHttpResponse[0];
    
    char statusLine[100];
    sprintf(statusLine, "%s%s%d%s%s%s", clientHttpReqMsgParams->httpReqVersion,
            HTTP_RSP_SP, 400, HTTP_RSP_SP, "Bad Request", HTTP_RSP_LF);
    
    strcpy(pBadRequestHttpResponse, statusLine);
    pBadRequestHttpResponse += strlen(statusLine);
    
    char contentTypeHeaderField[100];
    sprintf(contentTypeHeaderField, "%s%s%s%s", "Content-Type", ":"
            HTTP_RSP_SP, "text/html", HTTP_RSP_LF);
    
    strcpy(pBadRequestHttpResponse, contentTypeHeaderField);
    pBadRequestHttpResponse += strlen(contentTypeHeaderField);
    
    strcpy(pBadRequestHttpResponse, badRequestResponseBody);
    
    //printf("Bad Request Response : %s\n", badRequestHttpResponse);
    
    send(connId, badRequestHttpResponse, strlen(badRequestHttpResponse), 0);
}

void sendInternalServerErrorResponse(int connId)
{
    char internalServerErrorResponse[1024];
    char *pInternalServerErrorResponse = &internalServerErrorResponse[0];
    
    char statusLine[100];
    sprintf(statusLine, "%s%s%d%s%s%s", "HTTP/1.1",
            HTTP_RSP_SP, 500, HTTP_RSP_SP, "Internal Server Error: cannot allocate memory", HTTP_RSP_LFLF);
    
    strcpy(pInternalServerErrorResponse, statusLine);
    pInternalServerErrorResponse += strlen(statusLine);
    
    char contentTypeHeaderField[100];
    sprintf(contentTypeHeaderField, "%s%s%s%s", "Content-Type", ":"
            HTTP_RSP_SP, "text/html", HTTP_RSP_LF);
    
    strcpy(pInternalServerErrorResponse, contentTypeHeaderField);
    pInternalServerErrorResponse += strlen(contentTypeHeaderField);
    
    strcpy(pInternalServerErrorResponse, internalServerErrorResponseBody);
    
    printf("Internal Server Error Response : %s\n", internalServerErrorResponse);
    
    send(connId, internalServerErrorResponse, strlen(internalServerErrorResponse), 0);
}

void sendFileNotFoundResponse(int connId, http_req_msg_params clientHttpReqMsgParams)
{
    char notFoundHttpResponse[1024];
    char *pNotFoundHttpResponse = &notFoundHttpResponse[0];
    
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
    
    strcpy(pNotFoundHttpResponse, notFoundResponseBody);
    
    PRINT_DEBUG_MESSAGE("404 Not Found Response : %s\n", notFoundHttpResponse);
    
    send(connId, notFoundHttpResponse, strlen(notFoundHttpResponse), 0);
}
