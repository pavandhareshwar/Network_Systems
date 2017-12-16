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
#include <sys/msg.h>
#include <dispatch/dispatch.h>
#include <sys/semaphore.h>
#include <netdb.h>
#include <dirent.h>
#include <time.h>

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
    cacheTimeOut = atoi(argv[2]);
    
    memset(restOfHttpReqMsg, '\0', sizeof(restOfHttpReqMsg));
    
    /* Create a file to act as a hostname to IP address cache */
    FILE *fpLocalFileForHostNameToIpAddr = NULL;
    
    fpLocalFileForHostNameToIpAddr = fopen(LOCAL_DNS_CACHE_FILE, "r");
    if (fpLocalFileForHostNameToIpAddr)
    {
        /* File already exists. Not doing anything */
        fclose(fpLocalFileForHostNameToIpAddr);
    }
    else
    {
        /* File doesn't exist. Creating one */
        int fdescLocalFileForHostNameToIpAddr = open(LOCAL_DNS_CACHE_FILE, O_CREAT | O_EXCL, S_IRWXU | S_IRWXG | S_IRWXO);
        if (fdescLocalFileForHostNameToIpAddr)
        {
            printf("File %s created successfully\n", LOCAL_DNS_CACHE_FILE);
        }
        else
        {
            printf("File %s couldn't be created. Error : %s", LOCAL_DNS_CACHE_FILE, strerror(errno));
        }
        
        close(fdescLocalFileForHostNameToIpAddr);
    }
    
    FILE *fpDeleteFile = fopen("localDeleteFile.txt", "r");
    if (fpDeleteFile)
    {
        fclose(fpDeleteFile);
        remove("localDeleteFile.txt");
        printf("localDeleteFile.txt removed successfully\n");
    }
    
    fpDeleteFile = fopen("localDeleteFile_tmp.txt", "r");
    if (fpDeleteFile)
    {
        fclose(fpDeleteFile);
        remove("localDeleteFile_tmp.txt");
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
    
    /*  Bind (Associate the server socket created with the port number and
        the IP address.
     */
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
    
    if (signal(SIGINT, signalHandlerForParent) == SIG_ERR)
        printf("\ncan't catch SIGINT\n");
    
    /*  Listen for incoming connections on the server socket */
    /*  The server is blocked until it gets a connection request on the socket */
    listen(proxySock, /* socket descriptor */
           LISTEN_SYSCALL_BACKLOG /* maximum pending connection queued up */);
    
    printf("Waiting for incoming connections...\n");
    
#ifdef ENABLE_CACHE_EXPIRATION
    
    createQueueForCacheExpireProcess();
    
    createProcessToHandleCacheExpiration();
    
#endif
    
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
            printf("%s:%d:: accept failed, %s\n", __FUNCTION__,  __LINE__, strerror(errno));
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
            
            //printf("Created a child process for a new accepted connection, "
            //                    "PID: %d\n", getpid());
            
            /* Child process */
            /* Close the parent socket in the child process because we want
             the child process to handle the connection request and not
             listen for any connection requests.
             */
            close(proxySock);
            
            if (signal(SIGINT, signalHandlerForChildProc) == SIG_ERR)
                printf("\ncan't catch SIGINT\n");
            
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
            //printf("Killing process with pid: %d\n", getpid());
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
            printf("%s:%d:: fork failed, %s\n", __FUNCTION__,  __LINE__, strerror(errno));
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
        printf("%s:%d:: Malloc Failed\n", __FUNCTION__,  __LINE__);
        return -1;
    }
    
    /*  Create a memory key */
    if ((sharedMemoryKey = ftok("webproxy.c", 'R')) == -1)
    {
        perror("ftok");
        return -1;
    }
    
    //printf("Shared memory key (creation): %d\n", sharedMemoryKey);
    
    /*  Request for shared memory */
    if ((sharedMemoryId = shmget(sharedMemoryKey, SHM_SIZE, 0644 | IPC_CREAT)) == -1)
    {
        printf("%s:%d:: shmget failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        return -1;
    }
    
    /*  Attach the shared memory created to the process's address space */
    sharedMemoryDataPtr = shmat(sharedMemoryId, (void *)0, 0);
    if (sharedMemoryDataPtr == (hostNameToIpAddr *)(-1))
    {
        printf("%s:%d:: shmat failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        return -1;
    }
    
    /*  Initialize the shared memory and write proxyHostNameToIpAddrStruct structure
        data to it.
     */
    //printf("Writing to shared memory\n");
    memcpy(sharedMemoryDataPtr, &proxyHostNameToIpAddrStruct, sizeof(proxyHostNameToIpAddrStruct));
    
    /*  Detach the memory segment */
    if (shmdt(sharedMemoryDataPtr) == -1)
    {
        printf("%s:%d:: shmdt failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        return -1;
    }
    
    return 0;
}

void signalHandlerForChildProc(int sig)
{
    if (sig == SIGINT)
    {
        close(clientSock);
        exit(0);
    }
}

void signalHandlerForParent(int sig)
{
    printf("Signal Interrupt received. Gracefully exiting the server\n");
    if (sig == SIGINT)
    {
        key_t       sharedMemoryKey;
        int         sharedMemoryId;
        
#ifdef ENABLE_CACHE_EXPIRATION
        int         queueMsgId, queueMsgId1;
        key_t       queueKey, queueKey1;
        msgBuffer   queueSendBuffer, queueSendBuffer1;
        
        memset(&queueSendBuffer, '\0', sizeof(queueSendBuffer));
        memset(&queueSendBuffer1, '\0', sizeof(queueSendBuffer1));
#endif
        
        wait(NULL);
        printf("Closing proxy socket\n");
        
        close(proxySock);
        close(clientSock);
        
        /*  Create a memory key for shared memory */
        if ((sharedMemoryKey = ftok("webproxy.c", 'R')) == -1)
        {
            printf("%s:%d:: ftok failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            return;
        }
        
        //printf("Shared memory key (deletion): %d\n", sharedMemoryKey);
        
        /*  Get the shared memory */
        if ((sharedMemoryId = shmget(sharedMemoryKey, SHM_SIZE, 0644)) == -1)
        {
            printf("%s:%d:: shmget failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            return;
        }
        
        /* Destroy the shared memory created */
        if (shmctl(sharedMemoryId, IPC_RMID, NULL) != -1)
        {
            printf("Shared memory deleted successfully\n");
        }
        else
        {
            printf("%s:%d:: shmctl failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            return;
        }
        
#ifdef ENABLE_CACHE_EXPIRATION
        /* Create a memory key for message queue */
        if ((queueKey = ftok("webproxy.c", 'A')) == -1)
        {
            printf("%s:%d:: ftok failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        
        /* Identify the queue that we want to destroy */
        if ((queueMsgId = msgget(queueKey, 0644)) == -1)
        {
            printf("%s:%d:: msgget failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        
        /* Send a message to the queue to kill the child process */
        queueSendBuffer.msgType = 2;
        strcpy(queueSendBuffer.msgText, "processStop");
    
        int length = (int)strlen(queueSendBuffer.msgText);
        queueSendBuffer.msgText[length] = '\0';
        
        printf("Sending %s to message queue\n", queueSendBuffer.msgText);
        if (msgsnd(queueMsgId, &queueSendBuffer, length+1, 0) == -1)
        {
            printf("%s:%d:: msgsnd failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        
        /* Destroy the queue */
        if (msgctl(queueMsgId, IPC_RMID, NULL) == -1)
        {
            printf("%s:%d:: msgctl failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        else
        {
            printf("Message Queue deleted successfully\n");
        }
        
        sleep(1);
        
        /* Create a memory key for message queue */
        if ((queueKey1 = ftok("webproxy.c", 'F')) == -1)
        {
            printf("%s:%d:: ftok failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        
        /* Identify the queue that we want to destroy */
        if ((queueMsgId1 = msgget(queueKey1, 0644)) == -1)
        {
            printf("%s:%d:: msgget failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        
        /* Send a message to the queue to kill the child process */
        queueSendBuffer1.msgType = 1;
        strcpy(queueSendBuffer1.msgText, "processStop");
        
        int length1 = (int)strlen(queueSendBuffer1.msgText);
        queueSendBuffer1.msgText[length1] = '\0';
        
        printf("Sending %s to message queue\n", queueSendBuffer1.msgText);
        if (msgsnd(queueMsgId1, &queueSendBuffer1, length1+1, 0) == -1)
        {
            printf("%s:%d:: msgsnd failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        
        sleep(1);
        
        /* Destroy the queue */
        if (msgctl(queueMsgId1, IPC_RMID, NULL) == -1)
        {
            printf("%s:%d:: msgctl failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return;
        }
        else
        {
            printf("Message Queue deleted successfully\n");
        }
#endif
        
        exit(0);
    }
}

void createQueueForCacheExpireProcess(void)
{
    int     msgId;
    key_t   key;
    
    if ((key = ftok("webproxy.c", 'A')) == -1)
    {
        printf("%s:%d:: ftok failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        exit(1);
    }

    if ((msgId = msgget(key, 0644 | O_CREAT)) == -1)
    {
        printf("%s:%d:: msgget failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        exit(1);
    }
    
    printf("Queue successfully created for cache expiration process\n");
    
    return;
}

#ifdef ENABLE_CACHE_EXPIRATION
void createProcessToHandleCacheExpiration(void)
{
    pid_t childPid;
    
    childPid = fork();
    
    if (childPid == 0)
    {
        localFileLockSem = dispatch_semaphore_create(1);
        
        /*  Child Process */
        /*  We check the last modified time of the file and if exceeds the
            timeout value specified, then we delete the file.
         */
        
        printf("Created a process to handle cache expiration\n");
        
        if (signal(SIGINT, signalHandlerForCacheExpireProc) == SIG_ERR)
            printf("\ncan't catch SIGINT\n");
        
        createProcessToCheckCacheExpireFile();
        
        bool            canReadFromQueue = false;
        
        key_t           queueKey, queueKey1;
        int             queueMsgId = -1, queueMsgId1 = -1;
        msgBuffer       queueBuffer, queueBuffer1;
        
        bool            sentFirstMsgRcvdMsg = false;
        
        memset(&queueBuffer, '\0', sizeof(queueBuffer));
        memset(&queueBuffer1, '\0', sizeof(queueBuffer1));
        
        if ((queueKey = ftok("webproxy.c", 'A')) == -1)
        {
            printf("%s:%d:: ftok failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        }
        else
        {
            if ((queueMsgId = msgget(queueKey, 0644)) == -1)
            {
                printf("%s:%d:: msgget failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            }
            else
            {
                printf("Message Queue (handle cache expiration) identified\n");
                canReadFromQueue = true;
            }
        }
        
        if ((queueKey1 = ftok("webproxy.c", 'F')) == -1)
        {
            printf("%s:%d:: ftok failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        }
        else
        {
            if ((queueMsgId1 = msgget(queueKey1, 0644 | O_CREAT)) == -1)
            {
                printf("%s:%d:: msgget failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            }
            else
            {
                printf("Message Queue (check cache expire file parent) identified\n");
            }
        }
        
        while(1)
        {
            if (canReadFromQueue == true)
            {
                msgrcv(queueMsgId, &queueBuffer, sizeof(queueBuffer), 2, 0);
                
                //printf("Message from queue: %s\n", queueBuffer.msgText);
                if (strcmp(queueBuffer.msgText, "processStop") == 0)
                {
                    printf("Killing process that was created to handle cache expiration\n");
                    
                    dispatch_release(localFileLockSem);
                    //sem_destroy(&localFileLockSem);
                    
                    break;
                }
                
                writeToCacheFile(queueBuffer.msgText);
                
                //printContentsOfFile();
                
                if (false == sentFirstMsgRcvdMsg)
                {
                    queueBuffer1.msgType = 1;
                    strcpy(queueBuffer1.msgText, "Start");
                    
                    int length = (int)strlen(queueBuffer1.msgText);
                    queueBuffer1.msgText[length] = '\0';
                    
                    printf("Sending start message to the process handling file deletion\n");
                    msgsnd(queueMsgId1, &queueBuffer1, length+1, 0);
                    sentFirstMsgRcvdMsg = true;
                }
                
                memset(&queueBuffer, '\0', sizeof(queueBuffer));
            }
            
            sleep(2);
        }
        
        dispatch_release(localFileLockSem);
        //sem_destroy(&localFileLockSem);
        
        printf("Killed the process handling cache expiration\n");
        exit(0);
    }
    else if (childPid > 0)
    {
        /*  Parent process */
        return;
    }
    else
    {
        printf("%s:%d:: fork failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
    }
}

void signalHandlerForCacheExpireProc(int sig)
{
    if (sig == SIGINT)
    {
        exit(0);
    }
}

void createProcessToCheckCacheExpireFile(void)
{
    pid_t childPid;
    
    childPid = fork();
    
    if (childPid == 0)
    {
        printf("Created a process to handle cache file deletion\n");
        
        if (signal(SIGINT, signalHandlerForFileDeleteProc) == SIG_ERR)
            printf("\ncan't catch SIGINT\n");
        
        /* Child Process */
        key_t           queueKey;
        int             queueMsgId = -1;
        msgBuffer       queueBuffer;
        
        timeInfoStruct  timeInfo[100];
        
        bool            canReadFromQueue = false;
        
        for (int i = 0; i < 100; i++)
        {
            timeInfo[i].lastAccessTime = -1;
            timeInfo[i].lastModifiedTime = -1;
        }
        
        if ((queueKey = ftok("webproxy.c", 'F')) == -1)
        {
            printf("%s:%d:: ftok failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        }
        else
        {
            if ((queueMsgId = msgget(queueKey, 0644)) == -1)
            {
                printf("%s:%d:: msgget failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            }
            else
            {
                printf("Message Queue (handle file deletion) identified\n");
                canReadFromQueue = true;
            }
        }
        
        memset(&queueBuffer, '\0', sizeof(queueBuffer));
        
        while (canReadFromQueue == true)
        {
            msgrcv(queueMsgId, &queueBuffer, sizeof(queueBuffer), 1, 0);
            
            if (strcmp(queueBuffer.msgText, "Start") != 0)
            {
                continue;
            }
            else
            {
                printf("Received start message from parent process\n");
                break;
            }
        }
        
        
        bool    isDeleted = false;
        char    *buffer;
        size_t  numBytes = 512;
        ssize_t bytesRead = -1;
        
        buffer = malloc(numBytes*sizeof(char));
        
        while (1)
        {
            memset(&queueBuffer, '\0', sizeof(queueBuffer));
            msgrcv(queueMsgId, &queueBuffer, sizeof(queueBuffer), 1, IPC_NOWAIT);
            
            if (strcmp(queueBuffer.msgText, "processStop") == 0)
            {
                printf("Killing process that was created to handle cache expire file\n");
                
                break;
            }
            
            int curIndex = 0;
            
            FILE *fp = fopen("localDeleteFile.txt", "r");
            while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
            {
                //printContentsOfFile();
                //checkIfFileIsToBeDeleted(cacheBuffer[i], &timeInfoStruct[i], &isDeleted);
                //printf("Checking if file %s needs to be deleted\n", buffer);
                if (*buffer != '\0')
                {
                    checkIfFileIsToBeDeleted(buffer, &timeInfo[curIndex], &isDeleted);
                    
                    curIndex++;
                    
                    if (isDeleted == true)
                    {
                        fclose(fp);
                        deleteEntryFromLocalFile(buffer);
                        
                        //printContentsOfFile();
                        
                        fp = fopen("localDeleteFile.txt", "r");
                        /*  Check if file is empty. If it is, we would have to wait for the trigger
                         message again from the process handling client request */
                        curIndex--;
                    }
                }
                
                memset(buffer, '\0', numBytes);
            }
            fclose(fp);
            
            sleep(2);
        }
        
        free(buffer);
        printf("Killed the process handling cache file deletion\n");
        exit(0);
        
    }
    else if (childPid > 0)
    {
        /* Parent Process */
        return;
    }
    else
    {
        printf("%s:%d:: fork failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
    }
    
    return;
}

void signalHandlerForFileDeleteProc(int sig)
{
    if (sig == SIGINT)
    {
        exit(0);
    }
}

void printContentsOfFile(void)
{
    FILE *fpLocalFile = fopen("localDeleteFile.txt", "r");
    char fileName[512];
    
    memset(fileName, '\0', sizeof(fileName));
    
    printf("localDeleteFile.txt:: Contents: \n");
    if (fpLocalFile)
    {
        while (fgets(fileName, 512, fpLocalFile))
        {
            printf("%s", fileName);
        }
        fclose(fpLocalFile);
    }
    printf("\n");
}

//void writeToCacheFile(char *file, char **cacheBuffer, int cacheEntryIndex)
void writeToCacheFile(char *file)
{
    char    *buffer;
    size_t  numBytes = 120;
    ssize_t bytesRead;
    bool    entryExists = false;
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    PRINT_DEBUG_MESSAGE("Waiting for lock to write to cache file\n");
    //sem_wait(&localFileLockSem);
    dispatch_semaphore_wait(localFileLockSem, DISPATCH_TIME_FOREVER);

    FILE *fpDeleteFile = fopen("localDeleteFile.txt", "a");
    char fileWriteBuffer[512];
    
    entryExists = false;
    
    memset(fileWriteBuffer, '\0', sizeof(fileWriteBuffer));
    sprintf(fileWriteBuffer, "%s%c", file, '\n');
    
    FILE *fp = fopen("localDeleteFile.txt", "r");
    if (fp)
    {
        while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
        {
            int len = (int)strlen(buffer);
            buffer[len] = '\0';
            
            if(strstr(buffer, file))
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
        fwrite(fileWriteBuffer, sizeof(char), strlen(fileWriteBuffer), fpDeleteFile);
    }
    
    fclose(fpDeleteFile);
    
    dispatch_semaphore_signal(localFileLockSem);
    //sem_post(&localFileLockSem);
    PRINT_DEBUG_MESSAGE("Released lock for write to cache file\n");
    
    //printContentsOfFile();
    
    return;
}

void checkIfFileIsToBeDeleted(char *file, struct _timeInfoStruct_ *timeInfo, bool *deleted)
{
    //long lastAccessTime = -1;
    long lastModifiedTime = -1;
    
    struct timespec curTime;
    *deleted = false;
    
    if (*file == '\0')
    {
        return;
    }
    
    int fileLen = (int)strlen(file);
    if (*(file+fileLen-1) == '\n')
    {
        *(file+fileLen-1) = '\0';
    }
    
    //char accessTimeCommand[100];
    char modifiedTimeCommand[100];
    
    //memset(accessTimeCommand, '\0', sizeof(accessTimeCommand));
    memset(modifiedTimeCommand, '\0', sizeof(modifiedTimeCommand));
    
    //sprintf(accessTimeCommand, "%s %s %s > %s", "stat -f", "%a", file, "out.txt");
    //printf("accessTimeCommand: %s\n", accessTimeCommand);
    //system(accessTimeCommand);
    
    sprintf(modifiedTimeCommand, "%s %s %s > %s", "stat -f", "%m", file, "out.txt");
    //printf("modifiedTimeCommand: %s\n", modifiedTimeCommand);
    system(modifiedTimeCommand);
    
    clock_gettime(CLOCK_REALTIME, &curTime);
    
    FILE *fp = fopen("out.txt", "r");
    char buffer[512];
    
    memset(buffer, '\0', sizeof(buffer));
    if (fp)
    {
        fgets(buffer, 512, fp);
        fclose(fp);
        
        if (*buffer == '\0')
        {
            *deleted = false;
            return;
        }
        else
        {
            lastModifiedTime = atol(buffer);
        }
        remove("out.txt");
    }
    
    //printf("Current Time: %ld, Last Modified Time: %ld\n", curTime.tv_sec, lastModifiedTime);
    
    if ((curTime.tv_sec - lastModifiedTime) > cacheTimeOut)
    {
        printf("Its been %ld secs since last time %s (timeout = %d) was accessed. Deleting the file.\n",
               (curTime.tv_sec - lastModifiedTime), file, cacheTimeOut);
        
        if (remove(file) == -1)
        {
            printf("File %s delete failed\n", file);
        }
        else
        {
            printf("File %s deleted successfully\n", file);
            *deleted = true;
        }
    }
    
    return;
}

void deleteEntryFromLocalFile(char *lineToMatch)
{
    FILE    *fpRead = fopen("localDeleteFile.txt", "r");
    FILE    *fpWrite = fopen("localDeleteFile_tmp.txt", "r");
    
    PRINT_DEBUG_MESSAGE("Waiting for lock to delete an entry from cache file\n");
    //sem_wait(&localFileLockSem);
    dispatch_semaphore_wait(localFileLockSem, DISPATCH_TIME_FOREVER);
    
    fpWrite = fopen("localDeleteFile_tmp.txt", "w");
    
    char    *buffer;
    size_t  numBytes = 1024;
    ssize_t bytesRead = -1;
    
    char bufferCopy[1024];
    
    buffer = malloc(sizeof(char)*numBytes);
    
    while ((bytesRead = getline(&buffer, &numBytes, fpRead)) != -1)
    {
        memset(bufferCopy, '\0', sizeof(bufferCopy));
        strcpy(bufferCopy, buffer);
        int bufferLen = (int)strlen(bufferCopy);
        
        if (*(bufferCopy + bufferLen - 1) == '\n')
            *(bufferCopy + bufferLen - 1) = '\0';
        
        if (strcmp(bufferCopy, lineToMatch) == 0)
        {
            continue;
        }
        else
        {
            fwrite(buffer, sizeof(char), strlen(buffer), fpWrite);
        }
        
        memset(buffer, '\0', numBytes);
    }
    
    free(buffer);
    
    fclose(fpRead);
    fclose(fpWrite);
    
    char copySystemCommand[100];
    memset(copySystemCommand, '\0', sizeof(copySystemCommand));
    
    sprintf(copySystemCommand, "%s %s %s", "cp", "localDeleteFile_tmp.txt", "localDeleteFile.txt");
    
    system(copySystemCommand);
    
    //sem_post(&localFileLockSem);
    dispatch_semaphore_signal(localFileLockSem);
    PRINT_DEBUG_MESSAGE("Released lock for delete an entry from cache file\n");
    
    FILE *fp = fopen("localDeleteFile_tmp.txt", "r");
    if (fp)
    {
        fclose(fp);
        remove("localDeleteFile_tmp.txt");
    }
    
    return;
}
#endif

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
        
        char hostName[HOSTNAME_MAX_LEN];
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
        printf("%s:%d:: no data in socket: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
        retVal = -1;
    }
    else
    {
        /* read system call failed */
        printf("%s:%d:: read failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
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
        printf("%s:%d:: gethostbyname failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
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
            printf("%s:%d:: ftok failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            return;
        }
        
        /* connect to (and possibly create) the segment: */
        if ((sharedMemoryId = shmget(sharedMemoryKey, SHM_SIZE, 0644)) == -1)
        {
            printf("%s:%d:: shmget failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
            return;
        }
        
        /* attach to the segment to get a pointer to it: */
        sharedMemoryDataPtr = shmat(sharedMemoryId, (void *)0, 0);
        if (sharedMemoryDataPtr == (hostNameToIpAddr *)(-1))
        {
            printf("%s:%d:: shmat failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
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
            printf("%s:%d:: shmdt failed: %s\n", __FUNCTION__,  __LINE__, strerror(errno));
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
    
    FILE *fp = fopen(LOCAL_DNS_CACHE_FILE, "r");
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
        fp = fopen(LOCAL_DNS_CACHE_FILE, "a");
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
    int         cachedCopyExists = 0;
    
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
            printf("Cached copy exists for %s. Sending cached copy\n", clientHttpReqMsgParams.httpReqUri);
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
        
        //parseIndexFileForLinks(connId, fullFilePath);
#ifdef ENABLE_CACHE_PREFETCHING
        createProcessForPrefetching(connId, fullFilePath);
#endif
        
#ifdef ENABLE_CACHE_EXPIRATION
        sendMsgToCacheExpireQueue(fullFilePath);
#endif
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
    
    if (buffer)
    {
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
    }
    else
    {
        printf("%s:%d:: malloc failed: %s", __FUNCTION__,  __LINE__, strerror(errno));
    }
    
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
    char folderToCheck[FOLDER_NAME_MAX_LEN];
    char reqUrlCopy[REQ_URL_MAX_LEN];
    char folderName[FOLDER_NAME_MAX_LEN];
    char fileName[FOLDER_NAME_MAX_LEN];
    
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
            strcpy(folderName, hostName);
            strcpy(fileName, "index.html");
#endif
        }
        else
        {
            memcpy(subStr, subStr+1, strlen(subStr));
            strcpy(folderToCheck, subStr);
            
            char folderToCheckCopy[FOLDER_NAME_MAX_LEN];
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
                        char folderNameTemp[FOLDER_NAME_MAX_LEN];
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
    char fullFilePath[FOLDER_NAME_MAX_LEN];
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
        else
        {
            *found = false;
        }
        
        closedir(dir);
    }
    else
    {
        *found = false;
        char slashDelimiter[] = "/";
        char folderNameCopy[FOLDER_NAME_MAX_LEN];
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
    char *filePath;
    char fullFilePath[512];
    
    char reqUrlCopy[REQ_URL_MAX_LEN];
    memset(reqUrlCopy, '\0', sizeof(reqUrlCopy));
    
    strcpy(reqUrlCopy, clientHttpReqMsgParams.httpReqUri);
    
    memset(fullFilePath, '\0', sizeof(fullFilePath));
    if (strstr(reqUrlCopy, hostName))
    {
        filePath = strstr(reqUrlCopy, hostName);
        strcpy(fullFilePath, filePath);
    }
    else
    {
        char *filePath;
        filePath = strstr(reqUrlCopy, "http://");
        memcpy(filePath, filePath+7, strlen(filePath));
        sprintf(fullFilePath, "%s/%s", hostName, filePath);
    }
    char hostNameWithSlash[HOSTNAME_MAX_LEN];
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
    
    char reqUrlCopy[REQ_URL_MAX_LEN];
    memset(reqUrlCopy, '\0', sizeof(reqUrlCopy));
    
    strcpy(reqUrlCopy, clientHttpReqMsgParams.httpReqUri);
    
    char *filePath;
    char fullFilePath[512];
    
    memset(fullFilePath, '\0', sizeof(fullFilePath));
    if (strstr(reqUrlCopy, hostName))
    {
        filePath = strstr(reqUrlCopy, hostName);
        strcpy(fullFilePath, filePath);
    }
    else
    {
        char *filePath;
        filePath = strstr(reqUrlCopy, "http://");
        memcpy(filePath, filePath+7, strlen(filePath));
        sprintf(fullFilePath, "%s/%s", hostName, filePath);
    }
    
    char hostNameWithSlash[HOSTNAME_MAX_LEN];
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
    //printf("Opening file %s in write mode\n", fullFilePath);
    
    fpWtr = fopen(fullFilePath, "w");
    if (!fpWtr)
    {
        printf("%s:%d:: file open %s failed : %s\n", __FUNCTION__, __LINE__, fullFilePath, strerror(errno));
        return -1;
    }
    
    char ipAddr[100];
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
    
    //printf("Requesting %s from IP addr %s\n", fullFilePath, ipAddr);
    char proxyReqToServer[2048];
    memset(proxyReqToServer, '\0', sizeof(proxyReqToServer));
    
    composeHttpReqMsg(proxyHttpReqMsgParams, proxyReqToServer);
    
    //bcopy(hp->h_addr, &serverAddr.sin_addr, hp->h_length);
    serverAddr.sin_port = htons(serverPort);
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddr, &serverAddr.sin_addr);
    //memcpy(&serverAddr.sin_addr.s_addr, ipAddr, strlen(ipAddr));
    
    //int tcpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    if (tcpSocket < 0)
        printf("%s:%d:: socket creation failed: %s", __FUNCTION__,  __LINE__, strerror(errno));
    
    if (connect(tcpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
        printf("%s:%d:: connect failed: %s", __FUNCTION__,  __LINE__, strerror(errno));
    
    if (send(tcpSocket, proxyReqToServer, strlen(proxyReqToServer), 0) < 0)
        printf("%s:%d:: send failed: %s", __FUNCTION__,  __LINE__, strerror(errno));
    
#if 1
    char receiveBuffer[1024];
    memset(receiveBuffer, '\0', sizeof(receiveBuffer));
    
    ssize_t recvdBytes = -1;
    while ((recvdBytes = recv(tcpSocket, receiveBuffer, sizeof(receiveBuffer) , 0)) != 0)
    {
        fwrite(receiveBuffer, sizeof(char), recvdBytes, fpWtr);
        if (true == sendToClient)
        {
            write(connId, receiveBuffer, recvdBytes);
        }
        memset(receiveBuffer, '\0', sizeof(receiveBuffer));
        recvdBytes = -1;
    }
#else
    char receiveBuffer[500*1024];
    memset(receiveBuffer, '\0', sizeof(receiveBuffer));
    
    ssize_t recvdBytes = -1;
    recvdBytes = recv(tcpSocket, receiveBuffer, sizeof(receiveBuffer) , 0);
    printf("Received %ld bytes from server\n", recvdBytes);
    if (recvdBytes != 0)
    {
        fwrite(receiveBuffer, sizeof(char), recvdBytes, fpWtr);
        if (true == sendToClient)
        {
            write(connId, receiveBuffer, recvdBytes);
        }
    }
#endif
    printf("Saved contents to file %s\n", fullFilePath);
    
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
    char    ipAddressList[512];
    char    commaDeLimiter[] = ",";
    bool    matchFound = false;
    
    char    hostNameCopy[HOSTNAME_MAX_LEN];
    
    memset(ipAddressList, '\0', sizeof(ipAddressList));
    memset(hostNameCopy, '\0', sizeof(hostNameCopy));
    
    strcpy(hostNameCopy, hostName);
    memcpy(hostNameCopy, hostNameCopy+4, strlen(hostNameCopy)); // removing www. from hostname
    
    fp = fopen(LOCAL_DNS_CACHE_FILE, "r");
    if (!fp)
    {
        printf("file %s open failed\n", LOCAL_DNS_CACHE_FILE);
        performDNSquery = true;
    }
    else
    {
        buffer = (char *)malloc(numBytes*sizeof(char));
        
        while ((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
        {
            if (strstr(buffer, hostName) || strstr(buffer, hostNameCopy))
            {
                if (strstr(buffer, hostName))
                {
                    memcpy(buffer, buffer + strlen(hostName) + 1, strlen(buffer));
                }
                
                if (strstr(buffer, hostNameCopy))
                {
                    memcpy(buffer, buffer + strlen(hostNameCopy) + 1, strlen(buffer));
                }
                strcpy(ipAddressList, buffer);
                matchFound = true;
                break;
            }
        }
        
        if (matchFound == true)
        {
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
        }
        else
        {
            performDNSquery = true;
        }
        
        fclose(fp);
    }
    
    if (performDNSquery == true)
    {
        //printf("No entry exists for hostname %s in %s. Performing DNS lookup.\n", hostName, LOCAL_DNS_CACHE_FILE);
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
    
    sprintf(proxyReqToServer, "GET %s %s\r\n", proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqUri,
            proxyHttpReqMsgParams.clientHttpReqMsgParams.httpReqVersion);
    
    strcat(proxyReqToServer, restOfHttpReqMsg);
    
    int length = (int)strlen(proxyReqToServer);
    *(proxyReqToServer+length) = '\0';
    
    PRINT_DEBUG_MESSAGE("GET request to server: %s\n", proxyReqToServer);
    
    return;
}

#ifdef ENABLE_CACHE_PREFETCHING
void createProcessForPrefetching(int connId, char *fullFilePath)
{
    pid_t childPid;
    
    childPid = fork();
    if (childPid == 0)
    {
        /* Child process */
        /*  The child process created here will be used to handle
            pre-fetching
         */
        parseIndexFileForLinks(connId, fullFilePath);
        
        exit(0);
    }
    else if (childPid > 0)
    {
        /* Parent process */
        /* Do nothing */
        return;
    }
    else
    {
        printf("%s:%d:: fork failed: %s\n", __FUNCTION__, __LINE__, strerror(errno));
    }
    
    return;
}

void parseIndexFileForLinks(int connId, char *filePath)
{
    FILE    *fp = NULL;
    char    *buffer;
    size_t  numBytes = 256;
    ssize_t bytesRead;
    char    hrefStr[] = "a href=";
    //char    hrefStr[] = "href=";
    char    quoteDelimiter[] = "\"";
    char    slashDelimiter[] = "/";
    
    char    hostName[HOSTNAME_MAX_LEN];
    char    filePathCopy[FOLDER_NAME_MAX_LEN];
    char    folderNameToCheck[FOLDER_NAME_MAX_LEN];
    
    memset(hostName, '\0', sizeof(hostName));
    memset(filePathCopy, '\0', sizeof(filePathCopy));
    memset(folderNameToCheck, '\0', sizeof(folderNameToCheck));
    
    strcpy(filePathCopy, filePath);
    
    char *tokenH = strtok(filePathCopy, slashDelimiter);
    if (tokenH)
    {
        strcpy(hostName, tokenH);
    }
    
    http_req_msg_params clientHttpReqMsgParams;
    memset(&clientHttpReqMsgParams, '\0', sizeof(http_req_msg_params));
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    if (buffer)
    {
        if (strstr(filePath, ".htm") || strstr(filePath, ".html"))
        {
            //printf("Opening file %s\n", filePath);
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
                            if (token && (strstr(token, ".htm") || strstr(token, ".html") || strstr(token, ".edu")))
                            {
                                /*  Using the multiprocess approach here -
                                 Creating a new process for every accepted connection
                                 */
                                int cachedCopyExists = -1;
                                
                                if (strstr(token, hostName))
                                {
                                    strcpy(clientHttpReqMsgParams.httpReqUri, token);
                                    strcpy(folderNameToCheck, token);
                                }
                                else if (strstr(token, "http://"))
                                {
                                    strcpy(clientHttpReqMsgParams.httpReqUri, token);
                                    char tokenCopy[512];
                                    memset(tokenCopy, '\0', sizeof(tokenCopy));
                                    
                                    strcpy(tokenCopy, token);
                                    
                                    memcpy(tokenCopy, tokenCopy+7, strlen(tokenCopy));
                                    
                                    sprintf(folderNameToCheck, "%s/%s", hostName, tokenCopy);
                                }
                                else
                                {
                                    sprintf(clientHttpReqMsgParams.httpReqUri, "%s%s/%s", "http://", hostName, token);
                                    sprintf(folderNameToCheck, "%s/%s", hostName, token);
                                }
                                
                                strcpy(clientHttpReqMsgParams.httpReqMethod, "GET");
                                strcpy(clientHttpReqMsgParams.httpReqVersion, "HTTP/1.1");
                                
                                pid_t child_pid = fork();
                                if (child_pid == 0)
                                {
                                    //printf("Checking if cached copy of %s exists\n", folderNameToCheck);
                                    checkIfCachedCopyExists(folderNameToCheck, hostName, &cachedCopyExists);
                                    
                                    if (cachedCopyExists != -1)
                                    {
                                        if (cachedCopyExists == 0)
                                        {
                                            PRINT_DEBUG_MESSAGE("Call to sendHttpReqMsg with uri %s\n", clientHttpReqMsgParams.httpReqUri);
                                            sendHttpReqMsgToServer(connId, clientHttpReqMsgParams, hostName, false);
                                        }
                                            
                                        char fileNameCopy[FOLDER_NAME_MAX_LEN];
                                        
                                        memset(fileNameCopy, '\0', sizeof(fileNameCopy));
                                        strcpy(fileNameCopy, clientHttpReqMsgParams.httpReqUri);
                                        
                                        memcpy(fileNameCopy, fileNameCopy+7, strlen(fileNameCopy)); // Removing http://
                                        
                                        PRINT_DEBUG_MESSAGE("Call to prefetchDataForPrefetchedLinks with file %s\n", fileNameCopy);
                                        prefetchDataForPrefetchedLinks(connId, fileNameCopy, hostName);
                                    }
                                    exit(0);
                                }
                                else if (child_pid > 0)
                                {
                                    /* Do nothing */
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
                printf("%s:%d:: file open %s failed : %s\n", __FUNCTION__, __LINE__, filePath, strerror(errno));
                return;
            }
        }
        free(buffer);
    }
    else
    {
        printf("%s:%d:: malloc failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
    }
    
    return;
}

void prefetchDataForPrefetchedLinks(int connId, char *filePath, char *hostName)
{
    FILE    *fp = NULL;
    char    *buffer;
    size_t  numBytes = 256;
    ssize_t bytesRead;
    char    hrefStr[] = "href=";
    char    hrefStr1[] = "HREF=";
    char    imageStr[] = "img src=";
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    if (buffer)
    {
        //printf("Opening file %s\n", filePath);
        fp = fopen(filePath, "r");
        if (fp)
        {
            while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
            {
                int len = (int)strlen(buffer);
                buffer[len-1] = '\0';
                
                prefetchData(connId, filePath, hostName, buffer, hrefStr);
                
                prefetchData(connId, filePath, hostName, buffer, hrefStr1);
                
                prefetchData(connId, filePath, hostName, buffer, imageStr);
                
                memset((char *)buffer, '\0', sizeof(buffer));
            }
            fclose(fp);
        }
        else
        {
            printf("%s:%d:: file open %s failed : %s\n", __FUNCTION__, __LINE__, filePath, strerror(errno));
            return;
        }
        free(buffer);
    }
    else
    {
        printf("%s:%d:: malloc failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
    }
    
    return;
}

void prefetchData(int connId, char *filePath, char *hostName, char *buffer, char *refStr)
{
    char    *subStrPtr;
    char    quoteDelimiter[] = "\"";
    char    folderNameToCheck[FOLDER_NAME_MAX_LEN];
    
    char    filePathCopy[FOLDER_NAME_MAX_LEN];
    
    memset(filePathCopy, '\0', sizeof(filePathCopy));
    memset(folderNameToCheck, '\0', sizeof(folderNameToCheck));
    
    strcpy(filePathCopy, filePath);
    
    http_req_msg_params clientHttpReqMsgParams;
    memset(&clientHttpReqMsgParams, '\0', sizeof(http_req_msg_params));
    
    if (strstr(buffer, refStr))
    {
        subStrPtr = strstr(buffer, refStr);
        
        int length = (int)strlen(subStrPtr);
        char subStrCopy[length+1];
        memset(subStrCopy, '\0', sizeof(subStrCopy));
        
        strcpy(subStrCopy, subStrPtr);
        
        char *token = strtok(subStrCopy, quoteDelimiter);
        if (token)
        {
            token = strtok(NULL, quoteDelimiter);
            //if (token && (strstr(token, ".htm") || strstr(token, ".html")))
            {
                //printf("Checking if %s needs to be fetched or not\n", token);
                if (*token == '/')
                {
                    sprintf(clientHttpReqMsgParams.httpReqUri, "%s%s%s", "http://", hostName, token);
                    sprintf(folderNameToCheck, "%s%s", hostName, token);
                }
                else if (strstr(token, "http://"))
                {
                    strcpy(clientHttpReqMsgParams.httpReqUri, token);
                    char tokenCopy[512];
                    memset(tokenCopy, '\0', sizeof(tokenCopy));
                    
                    strcpy(tokenCopy, token);
                    
                    memcpy(tokenCopy, tokenCopy+7, strlen(tokenCopy));
                    
                    sprintf(folderNameToCheck, "%s/%s", hostName, tokenCopy);
                }
                else
                {
                    //strcpy(clientHttpReqMsgParams.httpReqUri, token);
                    //strcpy(folderNameToCheck, token);
                    
                    sprintf(clientHttpReqMsgParams.httpReqUri, "%s%s/%s", "http://", hostName, token);
                    sprintf(folderNameToCheck, "%s/%s", hostName, token);
                }
                /*  Using the multiprocess approach here -
                 Creating a new process for every accepted connection
                 */
                int cachedCopyExists = -1;
                
                strcpy(clientHttpReqMsgParams.httpReqMethod, "GET");
                strcpy(clientHttpReqMsgParams.httpReqVersion, "HTTP/1.1");
                
                pid_t child_pid = fork();
                if (child_pid == 0)
                {
                    checkIfCachedCopyExists(folderNameToCheck, hostName, &cachedCopyExists);
                    
                    if (cachedCopyExists != -1)
                    {
                        if (cachedCopyExists == 0)
                        {
                            PRINT_DEBUG_MESSAGE("Call to sendHttpReqMsg with uri %s\n", clientHttpReqMsgParams.httpReqUri);
                            sendHttpReqMsgToServer(connId, clientHttpReqMsgParams, hostName, false);
                        }
                        //else
                        //{
                        //    printf("Cached copy of %s exists\n", clientHttpReqMsgParams.httpReqUri);
                        //}
                    }
                    exit(0);
                }
                else if (child_pid > 0)
                {
                    /* Do nothing */
                }
                else
                {
                    //printf("fork failed, %s\n", strerror(errno));
                }
            }
        }
    }
}

#endif

#ifdef ENABLE_CACHE_EXPIRATION
int sendMsgToCacheExpireQueue(char *filePath)
{
    msgBuffer   queueBuffer;
    key_t       key;
    int         msgId;
    
    memset(&queueBuffer, '\0', sizeof(msgBuffer));
    
    if ((key = ftok("webproxy.c", 'A')) == -1)
    {
        printf("%s:%d:: ftok failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    if ((msgId = msgget(key, 0644)) == -1)
    {
        printf("%s:%d:: msgget failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    queueBuffer.msgType = 2;
    strcpy(queueBuffer.msgText, filePath);
    
    int length = (int)strlen(queueBuffer.msgText);
    queueBuffer.msgText[length] = '\0';
    
    //printf("Sending %s to message queue\n", filePath);
    if (msgsnd(msgId, &queueBuffer, length+1, 0) == -1)
    {
        printf("%s:%d:: msgsnd failed : %s\n", __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    return 0;
}
#endif

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

#if 0
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
#endif

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
