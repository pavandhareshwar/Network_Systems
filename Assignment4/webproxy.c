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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <netdb.h>
#include <dirent.h>

#include "webproxy.h"

int main(int argc, const char * argv[])
{
    proxySock = -1;
    clientSock = -1;
    
    /*  sockaddr_in structure for socket information about client and server */
    struct sockaddr_in proxySockAddr;
    char httpReqMsgBuffer[HTTP_REQ_MSG_MAX_LEN];
    memset(httpReqMsgBuffer, '\0', sizeof(httpReqMsgBuffer));
    
    if (argc < 3)
    {
        printf("Usage: webproxy <port_num> <timeout>\n");
        exit(1);
    }
    
    int proxyPortNum = atoi(argv[1]);
    //int timeout = atoi(argv[2]);
    //int fifoFileDesc = -1;
    
    memset(restOfHttpReqMsg, '\0', sizeof(restOfHttpReqMsg));
    
    /* Create a file to act as a hostname to IP address cache */
    FILE *fpLocalFileForHostNameToIpAddr = NULL;
    
    fpLocalFileForHostNameToIpAddr = fopen("hostNameToIpAddrCache.txt", "r");
    if (fpLocalFileForHostNameToIpAddr)
    {
        /* File already exists. Not doing anything */
        fclose(fpLocalFileForHostNameToIpAddr);
    }
    else
    {
        /* File doesn't exist. Creating one */
        int fdescLocalFileForHostNameToIpAddr = open("hostNameToIpAddrCache.txt", O_CREAT | O_EXCL, S_IRWXU | S_IRWXG | S_IRWXO);
        if (fdescLocalFileForHostNameToIpAddr)
        {
            printf("File %s created successfully\n", "hostNameToIpAddrCache.txt");
        }
        else
        {
            printf("File %s couldn't be created. Error : %s", "hostNameToIpAddrCache.txt", strerror(errno));
        }
        
        close(fdescLocalFileForHostNameToIpAddr);
    }
    
    intSignalReceived = false;
    
    for (int i = 0; i < MAX_HOST_NAMES; i++)
    {
        memset(proxyHostNameToIpAddrStruct.hostNameList[i], '\0', sizeof(proxyHostNameToIpAddrStruct.hostNameList[i]));
        memset(proxyHostNameToIpAddrStruct.ipAddrList[i], '\0', sizeof(proxyHostNameToIpAddrStruct.ipAddrList[i]));
    }
    
    proxyHostNameToIpAddrStruct.hostIndex = 0;
    
    int createShMRetVal = createSharedMemory();
    if (createShMRetVal == -1)
    {
        printf("createSharedMemory function failed\n");
        exit(1);
    }
    
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
    
    if (signal(SIGINT, signalHandler) == SIG_ERR)
        printf("\ncan't catch SIGINT\n");
    
    /*  Listen for incoming connections on the server socket */
    /*  The server is blocked until it gets a connection request on the socket */
    listen(proxySock, /* socket descriptor */
           LISTEN_SYSCALL_BACKLOG /* maximum pending connection queued up */);
    
    printf("Waiting for incoming connections...\n");
    
    //createChildProcessForTimeOutCheck();
    
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
            Creating a new process for every accepted connection
         */
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
            
            if (signal(SIGINT, signalForChildHandler) == SIG_ERR)
                printf("\ncan't catch SIGINT\n");
            
            memset(httpReqMsgBuffer, '\0', HTTP_REQ_MSG_MAX_LEN);
            
            int retVal = handleConnRequest(clientSock, httpReqMsgBuffer);
            if (retVal != 0)
            {
                printf("Handle Connection Request Failed\n");
            }
            
#if 0
            fifoFileDesc = open(timeoutFifo, O_WRONLY);
            if (fifoFileDesc < 0)
            {
                printf("Timeout fifo open failed\n");
            }
            
            char sendBuffer[100];
            memset(sendBuffer, '\0', sizeof(sendBuffer));
            
            strcpy(sendBuffer, "timeout");
            
            write(fifoFileDesc, sendBuffer, strlen(sendBuffer));
#endif
            
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

int createSharedMemory(void)
{
    /*  Shared memory in unix/linux systems can be created using
        the following steps:
        1.  Create a key to request the shared memory.
        2.  Request for shared memory using the memory key and memorize
            the returned shared memory ID.
        3.  Attach this shared memory to the process's address space.
        4.  Initialize the shared memory and perform some operation on it.
        5.  Detach the shared memory
        6.  When the shared memory isn't needed anymore, it needs to be deleted.
     */
    
    key_t               sharedMemoryKey;
    int                 sharedMemoryId;
    hostNameToIpAddr    *sharedMemoryDataPtr = malloc(20*100*1024*sizeof(char));
    if (sharedMemoryDataPtr == NULL)
    {
        printf("Malloc Failed\n");
        return -1;
    }
    
    /*  Create a memory key */
    if ((sharedMemoryKey = ftok("webproxy.c", 'R')) == -1)
    {
        perror("ftok");
        return -1;
    }
    
    /*  Request for shared memory */
    if ((sharedMemoryId = shmget(sharedMemoryKey, SHM_SIZE, 0644 | IPC_CREAT)) == -1)
    {
        perror("shmget");
        return -1;
    }
    
    /*  Attach the shared memory created to the process's address space */
    sharedMemoryDataPtr = shmat(sharedMemoryId, (void *)0, 0);
    if (sharedMemoryDataPtr == (hostNameToIpAddr *)(-1))
    {
        perror("shmat");
        return -1;
    }
    
    /*  Initialize the shared memory and write proxyHostNameToIpAddrStruct structure
        data to it.
     */
    printf("Writing to shared memory\n");
    memcpy(sharedMemoryDataPtr, &proxyHostNameToIpAddrStruct, sizeof(proxyHostNameToIpAddrStruct));
    
    /*  Detach the memory segment */
    if (shmdt(sharedMemoryDataPtr) == -1)
    {
        perror("shmdt");
        return -1;
    }
    
    return 0;
}

void signalForChildHandler(int sig)
{
    if (sig == SIGINT)
    {
        close(clientSock);
        exit(0);
    }
}

void signalHandler(int sig)
{
    printf("Signal Interrupt received. Gracefully exiting the server\n");
    if (sig == SIGINT)
    {
        key_t   sharedMemoryKey;
        int     sharedMemoryId;
        
        wait(NULL);
        printf("Closing proxy socket\n");
        
        /*  Create a memory key */
        if ((sharedMemoryKey = ftok("webproxy.c", 'R')) == -1)
        {
            perror("ftok");
            return;
        }
        
        /*  Request for shared memory */
        if ((sharedMemoryId = shmget(sharedMemoryKey, SHM_SIZE, 0644 | IPC_CREAT)) == -1)
        {
            perror("shmget");
            return;
        }
        
        /* Destroy the shared memory created */
        if (shmctl(sharedMemoryId, IPC_RMID, NULL) != -1)
        {
            printf("Shared memory deleted successfully\n");
        }
        else
        {
            perror("shmctl");
            return;
        }
        
        close(proxySock);
        close(clientSock);
        exit(0);
    }
}

void createChildProcessForTimeOutCheck(void)
{
    pid_t childPid;
    
    childPid = fork();
    
    if (childPid == 0)
    {
        /* Child Process */
        int fifoFileDesc = -1;
        char receiveBuffer[100];
        
        while (1)
        {
            fifoFileDesc = open(timeoutFifo, O_RDONLY);
            if (fifoFileDesc < 0)
            {
                printf("Timeout fifo open failed\n");
            }
            
            memset(receiveBuffer, '\0', sizeof(receiveBuffer));
            
            read(fifoFileDesc, receiveBuffer, sizeof(receiveBuffer));
            
            if (strcmp(receiveBuffer, "timeout") == 0)
            {
                char command[100];
                sprintf(command, "find %s -mmin %s%d -exec rm -rf {} \\;", "tempDir/*", "+", 1);
                printf("Command: %s\n", command);
                
                int systemCmdVal = system(command);
                if (systemCmdVal != 0)
                {
                    printf("System commmand failed\n");
                }
                else
                {
                    printf("System command success\n");
                }
            }
            else
            {
                /* Do nothing */
            }
        }
    }
    else if (childPid > 0)
    {
        /*  Parent process */
        /*  Create a FIFO here for the parent and child process
            to communicate with each other
         */
        
        /* Creating a fifo with mode as 666 */
        if (mkfifo(timeoutFifo, (((S_IRUSR) | (S_IWUSR)) | ((S_IRGRP) | (S_IWGRP)) | ((S_IROTH) | (S_IWOTH)))) != 0)
        {
            perror("mkfifo failed\n");
        }
        else
        {
            printf("Fifo created successfully\n");
        }
        return;
    }
}

int handleConnRequest(int connId, char *httpReqMsgBuffer)
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
        
        char httpReqMsgBufferCopy2[HTTP_REQ_MSG_MAX_LEN];
        memset(httpReqMsgBufferCopy2, '\0', sizeof(httpReqMsgBufferCopy2));
        strcpy(httpReqMsgBufferCopy2, httpReqMsgBuffer);
        
        char *ptrHttpReqMsgBufferCopy2 = &httpReqMsgBufferCopy2[0];
        
        if (*restOfHttpReqMsg == '\0')
        {
            while (*ptrHttpReqMsgBufferCopy2++ != '\n');
            
            strcpy(restOfHttpReqMsg, ptrHttpReqMsgBufferCopy2);
        }
        
        char hostName[100];
        memset(hostName, '\0', sizeof(hostName));
        
        char httpReqMsgBufferCopy[HTTP_REQ_MSG_MAX_LEN];
        memset(httpReqMsgBufferCopy, '\0', sizeof(httpReqMsgBufferCopy));
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
                
                PRINT_DEBUG_MESSAGE("==================================================================\n");
                PRINT_DEBUG_MESSAGE("HTTP Request Parameters: \n");
                PRINT_DEBUG_MESSAGE("HTTP Request Method : %s\n", clientHttpReqMsgParams.httpReqMethod);
                PRINT_DEBUG_MESSAGE("HTTP Request URI : %s\n", clientHttpReqMsgParams.httpReqUri);
                PRINT_DEBUG_MESSAGE("HTTP Request Version : %s\n", clientHttpReqMsgParams.httpReqVersion);
                PRINT_DEBUG_MESSAGE("==================================================================\n");
                
                //printf("HTTP Message: %s %s %s\n", clientHttpReqMsgParams.httpReqMethod, clientHttpReqMsgParams.httpReqUri, clientHttpReqMsgParams.httpReqVersion);
                
                bool validHostName = false;
                extractAndValidateHostName(httpReqMsgBuffer, &validHostName, hostName);
                
                if (validHostName == true)
                {
                    if (strcmp(clientHttpReqMsgParams.httpReqMethod, "GET") == 0)
                    {
                        /* Handle GET request */
                        retVal = handleGetRequest(connId, clientHttpReqMsgParams, hostName);
                        if (retVal == -1)
                        {
                            printf("handleGetRequest function failed\n");
                        }
                    }
                    else
                    {
                        /* Do Nothing */
                    }
                }
                else
                {
                    printf("Hostname Invalid\n");
                    sendBadRequestResponse(connId, &clientHttpReqMsgParams);
                    retVal = -1;
                }
            }
            else
            {
                printf("HTTP request line invalid\n");
            }
        }
        if (NULL != reqLineToken)
        {
            PRINT_DEBUG_MESSAGE("reqLineToken is NULL\n");
        }
        else
        {
            printf("reqLineToken is NULL\n");
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
    struct hostent      *hostEnt;
    struct in_addr      **addr_list;
    
    /* Shared memory parameters */
    key_t               sharedMemoryKey;
    int                 sharedMemoryId;
    hostNameToIpAddr    *sharedMemoryDataPtr;
    
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
        for (int i = 0; addr_list[i] != NULL; i++)
        {
            PRINT_DEBUG_MESSAGE("%s\n", inet_ntoa(*addr_list[i]));
        }
        
        /*  Save the hostname and the corresponding IP address information
            in a table so that we can look it up next time, rather than
            making a new hostname lookup API call. We also have to keep
            this information saved in the table for a certain pre-defined
            period of time, so that we have up-to-date information.
         */
        bool matchFound = false;
        int matchedIndex = -1;
        
        /* make the key: */
        if ((sharedMemoryKey = ftok("webproxy.c", 'R')) == -1)
        {
            perror("ftok");
            return;
        }
        
        /* connect to (and possibly create) the segment: */
        if ((sharedMemoryId = shmget(sharedMemoryKey, SHM_SIZE, 0644)) == -1)
        {
            perror("shmget");
            return;
        }
        
        /* attach to the segment to get a pointer to it: */
        sharedMemoryDataPtr = shmat(sharedMemoryId, (void *)0, 0);
        if (sharedMemoryDataPtr == (hostNameToIpAddr *)(-1))
        {
            perror("shmat");
            return;
        }
        
        for (int i = 0; i < MAX_HOST_NAMES; i++)
        {
            if (strcmp(sharedMemoryDataPtr->hostNameList[i], hostEnt->h_name) == 0)
            {
                PRINT_DEBUG_MESSAGE("Host Name Entry already exists at index %d\n", i);
                matchedIndex = i;
                matchFound = true;
                break;
            }
        }
        
        if (matchFound == false)
        {
            PRINT_DEBUG_MESSAGE("Host Name Entry doesn't exist. Copying %s at %d\n", hostEnt->h_name, sharedMemoryDataPtr->hostIndex);
            strcpy(sharedMemoryDataPtr->hostNameList[sharedMemoryDataPtr->hostIndex], hostEnt->h_name);
            for (int i = 0; addr_list[i] != NULL; i++)
            {
                char ipAddrToAddWithComma[50];
                memset(ipAddrToAddWithComma, '\0', sizeof(ipAddrToAddWithComma));
                sprintf(ipAddrToAddWithComma, "%s%s", inet_ntoa(*addr_list[i]), ",");
                strcat(sharedMemoryDataPtr->ipAddrList[sharedMemoryDataPtr->hostIndex], ipAddrToAddWithComma);
            }
            
            int length = (int)strlen(sharedMemoryDataPtr->ipAddrList[sharedMemoryDataPtr->hostIndex]);
            if (sharedMemoryDataPtr->ipAddrList[sharedMemoryDataPtr->hostIndex][length-1] == ',')
                sharedMemoryDataPtr->ipAddrList[sharedMemoryDataPtr->hostIndex][length-1] = '\0';
            
            sharedMemoryDataPtr->hostIndex++;
        }
        else
        {
            for(int i = 0; addr_list[i] != NULL; i++)
            {
                char ipAddrToAddWithComma[50];
                memset(ipAddrToAddWithComma, '\0', sizeof(ipAddrToAddWithComma));
                sprintf(ipAddrToAddWithComma, "%s%s", inet_ntoa(*addr_list[i]), ",");
                strcat(proxyHostNameToIpAddrStruct.ipAddrList[matchedIndex], ipAddrToAddWithComma);
            }
            
            int length = (int)strlen(sharedMemoryDataPtr->ipAddrList[matchedIndex]);
            if (sharedMemoryDataPtr->ipAddrList[sharedMemoryDataPtr->hostIndex][length-1] == ',')
                sharedMemoryDataPtr->ipAddrList[matchedIndex][length-1] = '\0';
        }
        
        for (int i = 0; i < sharedMemoryDataPtr->hostIndex; i++)
        {
            PRINT_DEBUG_MESSAGE("HostName and IP addresses:: [%d] %s : %s\n",
                                i, sharedMemoryDataPtr->hostNameList[i], sharedMemoryDataPtr->ipAddrList[i]);
        }
        
        for (int i = 0; i < sharedMemoryDataPtr->hostIndex; i++)
        {
            writeHostNameToIpAddrToLocalFile(sharedMemoryDataPtr->hostNameList[i],
                                             sharedMemoryDataPtr->ipAddrList[i]);
        }
        
        /*  Detach the memory segment */
        if (shmdt(sharedMemoryDataPtr) == -1)
        {
            perror("shmdt");
            return;
        }
    }
}

void writeHostNameToIpAddrToLocalFile(char *hostName, char *ipAddress)
{
    /*  Check if the entry that we want to write already exists in the local file.
        If not, write the information to the local file. If yes, then skip the write.
     */
    
    char    *buffer;
    size_t  numBytes = 120;
    ssize_t bytesRead;
    bool    entryExists = false;
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    FILE *fp = fopen("hostNameToIpAddrCache.txt", "r");
    if (fp)
    {
        while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
        {
            int len = (int)strlen(buffer);
            buffer[len-1] = '\0';
            
            if((strstr(buffer, hostName)) && (strstr(buffer, ipAddress)))
            {
                PRINT_DEBUG_MESSAGE("Entry already exists\n");
                entryExists = true;
                break;
            }
        }
        fclose(fp);
    }
        
    if (entryExists == false)
    {
        fp = fopen("hostNameToIpAddrCache.txt", "a");
        if (fp)
        {
            PRINT_DEBUG_MESSAGE("Entry doesn't exist\n");
            char writeBuffer[100];
            memset(writeBuffer, '\0', sizeof(writeBuffer));
            
            sprintf(writeBuffer, "%s:%s\n", hostName, ipAddress);
            fwrite(writeBuffer, sizeof(char), strlen(writeBuffer), fp);
            
            fclose(fp);
        }
        else
        {
            printf("File Open failed to write hostName to IP address translation\n");
        }
    }
    
    free(buffer);
    
    return;
}

int handleGetRequest(int connId, http_req_msg_params clientHttpReqMsgParams, char *hostName)
{
    int cachedCopyExists = 0;
    
    int blockCheckRetVal = checkIfHostIsBlocked(hostName);
    if (blockCheckRetVal == -1)
    {
        sendForbiddenResponse(connId, clientHttpReqMsgParams);
        exit(1);
    }
    
    checkIfCachedCopyExists(clientHttpReqMsgParams.httpReqUri, hostName, &cachedCopyExists);
    
    if (cachedCopyExists != -1)
    {
        if (cachedCopyExists == 0)
        {
            sendHttpReqMsgToServer(connId, clientHttpReqMsgParams, hostName, true);
        }
        else
        {
            printf("Cached copy exists. Sending cached copy\n");
            sendCachedCopyToClient(connId, clientHttpReqMsgParams, hostName);
        }
        
        char reqUrlCopy[256];
        memset(reqUrlCopy, '\0', sizeof(reqUrlCopy));
        
        strcpy(reqUrlCopy, clientHttpReqMsgParams.httpReqUri);
        
        char *fullFilePath = strstr(reqUrlCopy, hostName);
        char hostNameWithSlash[100];
        memset(hostNameWithSlash, '\0', sizeof(hostNameWithSlash));
        
        sprintf(hostNameWithSlash, "%s%s", hostName, "/");
        
        if (strcmp(fullFilePath, hostNameWithSlash) == 0)
        {
#ifdef USE_TEMP_DIRECTORY
            sprintf(fullFilePath, "%s/%s%s", "tempDir", hostNameWithSlash, "index.html");
#else
            sprintf(fullFilePath, "%s%s", hostNameWithSlash, "index.html");
#endif
        }
#ifdef USE_TEMP_DIRECTORY
        else
        {
            sprintf(fullFilePath, "%s/%s", "tempDir", hostNameWithSlash);
        }
#endif
        
        parseIndexFileForLinks(connId, fullFilePath);
    }
    
    return 0;
}

int checkIfHostIsBlocked(char *hostName)
{
    int     retVal = -1;
    char    *buffer;
    size_t  numBytes = 120;
    ssize_t bytesRead;
    bool    blockHost = false;
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    FILE *fp = fopen("websites_deny.txt", "r");
    if (fp)
    {
        while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
        {
            int len = (int)strlen(buffer);
            buffer[len-1] = '\0';
            
            if(strcmp(buffer, hostName) == 0)
            {
                PRINT_DEBUG_MESSAGE("Hostname %s in website deny list\n", hostName);
                blockHost = true;
                break;
            }
        }
        PRINT_DEBUG_MESSAGE("Hostname %s not in websites denied list\n", hostName);
        fclose(fp);
    }
    
    free(buffer);
    
    if (blockHost == false)
    {
        retVal = 0;
    }
    else
    {
        retVal = -1;
    }
    
    return retVal;
}

void checkIfCachedCopyExists(char *reqUrl, char *hostName, int *cachedCopyExists)
{
    char folderToCheck[100];
    char reqUrlCopy[100];
    char folderName[100];
    char fileName[100];
    
    memset(folderToCheck, '\0', sizeof(folderToCheck));
    memset(reqUrlCopy, '\0', sizeof(reqUrlCopy));
    memset(folderName, '\0', sizeof(folderName));
    memset(fileName, '\0', sizeof(fileName));
    
    strcpy(reqUrlCopy, reqUrl);
    
    char *subStr = strstr(reqUrlCopy, hostName);
    if (subStr)
    {
        memcpy(subStr, subStr+strlen(hostName), strlen(subStr));
        if (*subStr == '/' && *(subStr+1) == '\0')
        {
#ifdef USE_TEMP_DIRECTORY
            sprintf(folderName, "%s/%s", "tempDir", hostName);
            strcpy(fileName, "index.html");
#else
            strcpy(fileName, "/");
#endif
        }
        else
        {
            memcpy(subStr, subStr+1, strlen(subStr));
            strcpy(folderToCheck, subStr);
            
            char folderToCheckCopy[100];
            memset(folderToCheckCopy, '\0', sizeof(folderToCheckCopy));
            
            strcpy(folderToCheckCopy, folderToCheck);
            
            /*  If the requested file is an html file or an image file
                then skip this whole process.
             */
            if (strstr(folderToCheckCopy, "/"))
            {
                /*  Extracting the folderName and fileName that needs to be checked
                    to see if we have a local copy or request from the server.
                 */
                for (int i = (int)strlen(folderToCheckCopy); i > 0; i--)
                {
                    if (folderToCheckCopy[i] == '/')
                    {
                        char folderNameTemp[100];
                        memset(folderNameTemp, '\0', sizeof(folderNameTemp));
                        strncpy(folderNameTemp, folderToCheckCopy, i);
#ifdef USE_TEMP_DIRECTORY
                        sprintf(folderName, "%s/%s/%s", "tempDir", hostName, folderNameTemp);
#else
                        sprintf(folderName, "%s/%s", hostName, folderNameTemp);
#endif
                        strcpy(fileName, folderToCheckCopy+i+1);
                        break;
                    }
                }
            }
            else
            {
                strcpy(folderName, hostName);
                strcpy(fileName, subStr);
            }
        }
    }
    
    PRINT_DEBUG_MESSAGE("reqUrl: %s, folderName: %s, fileName: %s\n", reqUrl, folderName, fileName);
    
    bool found = 0;
#ifdef USE_TEMP_DIRECTORY
    checkIfDirAndFileExists(folderName, fileName, &found);
        
    if (found == true)
    {
        *cachedCopyExists = 1;
    }
    else
    {
        *cachedCopyExists = 0;
    }
#else
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
#endif
    
    return;
}

void checkIfDirAndFileExists(char *folderName, char *fileName, bool *found)
{
    char fullFilePath[100];
    memset(fullFilePath, '\0', sizeof(fullFilePath));
    sprintf(fullFilePath, "%s/%s", folderName, fileName);
    
    //printf("fullFilePath: %s\n", fullFilePath);
    
    DIR* dir = opendir(folderName);
    if (dir)
    {
        /* Directory exists. */
        PRINT_DEBUG_MESSAGE("Directory %s exists\n", folderName);
    
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
        *found = false;
        char slashDelimiter[] = "/";
        char folderNameCopy[100];
        memset(folderNameCopy, '\0', sizeof(folderNameCopy));
        
        strcpy(folderNameCopy, folderName);
        
        PRINT_DEBUG_MESSAGE("Directory %s doesn't exist\n", folderName);
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
#ifdef USE_TEMP_DIRECTORY
        sprintf(fullFilePath, "%s/%s%s", "tempDir", hostNameWithSlash, "index.html");
#else
        sprintf(fullFilePath, "%s%s", fullFilePath, "index.html");
#endif
    }
#ifdef USE_TEMP_DIRECTORY
    else
    {
        sprintf(fullFilePath, "%s/%s", "tempDir", hostNameWithSlash);
    }
#endif
    //printf("fullFilePath: %s\n", fullFilePath);
    
    FILE *fpRd = NULL;
    int fileSize = -1;
    fpRd = fopen(fullFilePath, "r");
    if (!fpRd)
    {
        printf("File Open %s failed\n", fullFilePath);
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

int sendHttpReqMsgToServer(int connId, http_req_msg_params clientHttpReqMsgParams,
                           char *hostName, bool sendToClient)
{
    int retVal = -1;
    struct sockaddr_in serverAddr;
    int serverPort = 80;
    
    char reqUrlCopy[256];
    memset(reqUrlCopy, '\0', sizeof(reqUrlCopy));
    
    strcpy(reqUrlCopy, clientHttpReqMsgParams.httpReqUri);
    
    char *fullFilePath = strstr(reqUrlCopy, hostName);
    char hostNameWithSlash[100];
    memset(hostNameWithSlash, '\0', sizeof(hostNameWithSlash));
    
    sprintf(hostNameWithSlash, "%s%s", hostName, "/");
    
    if (strcmp(fullFilePath, hostNameWithSlash) == 0)
    {
#ifdef USE_TEMP_DIRECTORY
        sprintf(fullFilePath, "%s/%s%s", "tempDir", hostNameWithSlash, "index.html");
#else
        sprintf(fullFilePath, "%s%s", hostNameWithSlash, "index.html");
#endif
    }
#ifdef USE_TEMP_DIRECTORY
    else
    {
        sprintf(fullFilePath, "%s/%s", "tempDir", hostNameWithSlash);
    }
#endif
    //printf("fullFilePath: %s\n", fullFilePath);

    FILE *fpWtr = NULL;
    PRINT_DEBUG_MESSAGE("Opening file %s in write mode\n", fullFilePath);
    
    fpWtr = fopen(fullFilePath, "w");
    if (!fpWtr)
    {
        perror("File Open failed\n");
        return -1;
    }
    
    char ipAddr[100];
    int ipAddrLen = -1;
    
    memset(ipAddr, '\0', sizeof(ipAddr));
    checkIpForHostNameInLocalFile(hostName, ipAddr);
    
    proxy_http_req_msg_params proxyHttpReqMsgParams;
    memset(&proxyHttpReqMsgParams, '\0', sizeof(proxyHttpReqMsgParams));
    
    strcpy(proxyHttpReqMsgParams.hostName, hostName);
    memcpy(&proxyHttpReqMsgParams.clientHttpReqMsgParams, &clientHttpReqMsgParams, sizeof(clientHttpReqMsgParams));
    //strcpy(proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqMethod, clientHttpReqMsgParams.httpReqMethod);
    //strcpy(proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqUri, clientHttpReqMsgParams.httpReqUri);
    //strcpy(proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqVersion, clientHttpReqMsgParams.httpReqVersion);
    
    /*  If the proxy server doesn't have the contents requested by the
        client, then it will compose an HTTP request message to the
        webserver and get the contents from the webserver and send it
        to the client as part of the response message.
     */
    
    char proxyReqToServer[2048];
    memset(proxyReqToServer, '\0', sizeof(proxyReqToServer));
    
    composeHttpReqMsg(proxyHttpReqMsgParams, proxyReqToServer);
    
    //bcopy(hp->h_addr, &serverAddr.sin_addr, hp->h_length);
    serverAddr.sin_port = htons(serverPort);
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddr, &serverAddr.sin_addr);
    
    int tcpSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (tcpSocket < 0)
        printf("Error opening socket\n");
    
    if (connect(tcpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
        printf("Error Connecting\n");
    
    if (send(tcpSocket, proxyReqToServer, strlen(proxyReqToServer), 0) < 0)
        printf("Error with send()\n");
    
    char receiveBuffer[1024];
    memset(receiveBuffer, '\0', sizeof(receiveBuffer));
    
    printf("Saving contents to file %s\n", fullFilePath);
    ssize_t recvdBytes = -1;
    while ((recvdBytes = recv(tcpSocket, receiveBuffer, sizeof(receiveBuffer) - 1 , 0)) != 0)
    {
        fwrite(receiveBuffer, sizeof(char), recvdBytes, fpWtr);
        if (true == sendToClient)
        {
            write(connId, receiveBuffer, recvdBytes);
        }
        memset(receiveBuffer, '\0', sizeof(receiveBuffer));
    }
    
    fclose(fpWtr);
    
    close(tcpSocket);
    
    retVal = 0;
    
    return retVal;
}

void checkIpForHostNameInLocalFile(char *hostName, char *ipAddr)
{
    struct hostent *hp;
    
    FILE    *fp = NULL;
    char    *buffer = NULL;
    size_t  numBytes = 256;
    ssize_t bytesRead;
    bool    performDNSquery = false;
    char    ipAddressList[100];
    char    commaDeLimiter[] = ",";
    
    memset(ipAddressList, '\0', sizeof(ipAddressList));
    
    fp = fopen("hostNameToIpAddrCache.txt", "r");
    if (!fp)
    {
        printf("file %s open failed\n", "hostNameToIpAddrCache.txt");
        performDNSquery = true;
    }
    else
    {
        buffer = (char *)malloc(numBytes*sizeof(char));
        
        while ((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
        {
            if (strstr(buffer, hostName))
            {
                memcpy(buffer, buffer + strlen(hostName) + 1, strlen(buffer));
                strcpy(ipAddressList, buffer);
                break;
            }
        }
        
        if (*(ipAddressList + strlen(ipAddressList) - 1) == '\n')
            *(ipAddressList + strlen(ipAddressList) - 1) = '\0';
        
        if (strstr(ipAddressList, ","))
        {
            char *token = strtok(ipAddressList, commaDeLimiter);
            while (token)
            {
                printf("%d: token: %s\n", __LINE__, token);
                bool ipAddrWorks = false;
                testIpAddress(ipAddressList, &ipAddrWorks);
                if (ipAddrWorks == true)
                {
                    strcpy(ipAddr, ipAddressList);
                    performDNSquery = false;
                    break;
                }
                else
                {
                    token = strtok(NULL, commaDeLimiter);
                }
            }
        }
        else
        {
            bool ipAddrWorks = false;
            testIpAddress(ipAddressList, &ipAddrWorks);
            
            if (ipAddrWorks == true)
            {
                strcpy(ipAddr, ipAddressList);
                performDNSquery = false;
            }
            else
            {
                performDNSquery = true;
            }
        }
        fclose(fp);
    }
    
    if (performDNSquery == true)
    {
        if((hp = gethostbyname(hostName)) == NULL)
        {
            herror("gethostbyname");
            return;
        }
        
        struct in_addr  **addr_list;
        bool            ipAddrWorks = false;
        
        addr_list = (struct in_addr **)hp->h_addr_list;
        
        for (int i = 0; addr_list[i] != NULL; i++)
        {
            testIpAddress(ipAddressList, &ipAddrWorks);
            if (ipAddrWorks == true)
            {
                strcpy(ipAddr, inet_ntoa(*addr_list[i]));
                break;
            }
        }
    }
}

void testIpAddress(char *ipAddrToTest, bool *ipAddrWorks)
{
    struct sockaddr_in serverAddr;
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0)
        printf("Error opening socket\n");
    
    memset(&serverAddr, '\0', sizeof(serverAddr));
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    inet_pton(AF_INET, ipAddrToTest, &serverAddr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
    {
        printf("Error Connecting\n");
        *ipAddrWorks = false;
    }
    else
    {
        *ipAddrWorks = true;
    }
    
    close(sockfd);
}

void composeHttpReqMsg(proxy_http_req_msg_params proxyHttpReqMsgParams, char *proxyReqToServer)
{
    //sprintf(proxyReqToServer, "GET %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\n\r\n",
    //        proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqUri , proxyHttpReqMsgParams.hostName);
    
    sprintf(proxyReqToServer, "GET %s HTTP/1.1\r\n", proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqUri);
    
    strcat(proxyReqToServer, restOfHttpReqMsg);
    
    PRINT_DEBUG_MESSAGE("GET request to server: %s\n", proxyReqToServer);
    
    return;
}

void parseIndexFileForLinks(int connId, char *filePath)
{
    FILE    *fp = NULL;
    char    *buffer;
    size_t  numBytes = 256;
    ssize_t bytesRead;
    char    hrefStr[] = "href=";
    char    quoteDelimiter[] = "\"";
    char    slashDelimiter[] = "/";
    
    char    hostName[100];
    char    filePathCopy[512];
    
    memset(hostName, '\0', sizeof(hostName));
    memset(filePathCopy, '\0', sizeof(filePathCopy));
    
    strcpy(filePathCopy, filePath);
    
    char *tokenH = strtok(filePathCopy, slashDelimiter);
    if (tokenH)
    {
        strcpy(hostName, tokenH);
    }
    
    http_req_msg_params clientHttpReqMsgParams;
    memset(&clientHttpReqMsgParams, '\0', sizeof(http_req_msg_params));
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    if (strstr(filePath, ".htm") || strstr(filePath, ".html"))
    {
        printf("Opening file %s\n", filePath);
        fp = fopen(filePath, "r");
        if (fp)
        {
            while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
            {
                int len = (int)strlen(buffer);
                buffer[len-1] = '\0';
                
                char *subStrPtr = strstr(buffer, hrefStr);
                if (subStrPtr)
                {
                    int length = (int)strlen(subStrPtr);
                    char subStrCopy[length+1];
                    memset(subStrCopy, '\0', sizeof(subStrCopy));
                    
                    strcpy(subStrCopy, subStrPtr);
                    
                    char *token = strtok(subStrCopy, quoteDelimiter);
                    if (token)
                    {
                        token = strtok(NULL, quoteDelimiter);
                        if (token && (strstr(token, ".htm") || strstr(token, ".html")))
                        {
                            /*  Using the multiprocess approach here -
                                Creating a new process for every accepted connection
                             */
                            int cachedCopyExists = -1;
                            
                            strcpy(clientHttpReqMsgParams.httpReqUri, token);
                            strcpy(clientHttpReqMsgParams.httpReqMethod, "GET");
                            strcpy(clientHttpReqMsgParams.httpReqVersion, "HTTP/1.1");
                            
                            pid_t child_pid = fork();
                            if (child_pid == 0)
                            {
                                checkIfCachedCopyExists(token, hostName, &cachedCopyExists);
                                
                                if (cachedCopyExists != -1)
                                {
                                    if (cachedCopyExists == 0)
                                    {
                                        //printf("Call to sendHttpReqMsg with uri %s\n", clientHttpReqMsgParams.httpReqUri);
                                        sendHttpReqMsgToServer(connId, clientHttpReqMsgParams, hostName, false);
                                    }
                                }
                                close(child_pid);
                            }
                            else if (child_pid > 0)
                            {
                                close(child_pid);
                            }
                            else
                            {
                                //printf("fork failed, %s\n", strerror(errno));
                            }
                        }
                    }
                }
                memset((char *)buffer, '\0', sizeof(buffer));
            }
            fclose(fp);
        }
        else
        {
            printf("File Open failed\n");
            return;
        }
    }
    
    
    free(buffer);
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

void sendForbiddenResponse(int connId, http_req_msg_params clientHttpReqMsgParams)
{
    char forbiddenHttpResponse[1024];
    memset(forbiddenHttpResponse, '\0', sizeof(forbiddenHttpResponse));
    char *pForbiddenHttpResponse = &forbiddenHttpResponse[0];
    
    char statusLine[100];
    sprintf(statusLine, "%s%s%d%s%s%s", clientHttpReqMsgParams.httpReqVersion,
            HTTP_RSP_SP, 403, HTTP_RSP_SP, "Forbidden", HTTP_RSP_LF);
    
    strcpy(pForbiddenHttpResponse, statusLine);
    pForbiddenHttpResponse += strlen(statusLine);
    
    char contentTypeHeaderField[100];
    sprintf(contentTypeHeaderField, "%s%s%s%s", "Content-Type", ":"
            HTTP_RSP_SP, "text/html", HTTP_RSP_LF);
    
    strcpy(pForbiddenHttpResponse, contentTypeHeaderField);
    pForbiddenHttpResponse += strlen(contentTypeHeaderField);
    
    strcpy(pForbiddenHttpResponse, forbiddenRequestResponseBody);
    
    PRINT_DEBUG_MESSAGE("403 Forbidden Response : %s\n", forbiddenHttpResponse);
    
    send(connId, forbiddenHttpResponse, strlen(forbiddenHttpResponse), 0);
}
