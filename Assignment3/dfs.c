#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <unistd.h>     //write
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "dfs.h"

int main(int argc, char *argv[])
{
    struct sockaddr_in dfsServerSockAddr;
    char fileDataBuffer[FILE_DATA_MAX_LEN];
    
    memset(fileDataBuffer, '\0', sizeof(fileDataBuffer));
    
    /*  Check command-line arguments
        The dfs should be run as follows:
        dfs <dfs_homeDir> <portNum>
     */
    if (argc < 3)
    {
        printf("Usage: dfs <dfs_homeDir> <portNum>\n");
        exit(1);
    }
    
    /* Server socket */
    int dfsServerSockDesc = -1;
    
    /* Client socket */
    int dfsclientSockDesc = -1;
    
    strcpy(dfsServerParams.dfsDirectory, argv[1]);
    dfsServerParams.dfsPortNum = atoi(argv[2]);
    
    checkIfDirectoryExists(dfsServerParams.dfsDirectory);
    
    char configFile[] = "dfs.conf";
    
    int configFileRetVal = readDFServerConfigFile(configFile, &dfsServerParams);
    if (configFileRetVal)
    {
        printf("readDFServerConfigFile failed\n");
    }
    else
    {
        printDFServerConfigParams(dfsServerParams);
    }
    
    int sockCreateandBindRetVal = createSocketAndBind(&dfsServerSockAddr, dfsServerParams, &dfsServerSockDesc);
    if (sockCreateandBindRetVal)
    {
        printf("Socket Creation or Bind failed\n");
        exit(1);
    }
    
    /*  Listen for incoming connections on the server socket */
    /*  The server is blocked until it gets a connection request on the socket */
    listen(dfsServerSockDesc, /* socket descriptor */
           LISTEN_SYSCALL_BACKLOG /* maximum pending connection queued up */);
    
    printf("Waiting for connection request from the client\n");
    
    struct sockaddr_in clientSockAddr;
    socklen_t clientAddrLen = -1;
    
    /* Accept an incoming connection */
    dfsclientSockDesc = accept(dfsServerSockDesc, /* socket descriptor */
                        (struct sockaddr *)&clientSockAddr, /* sockaddr structure */
                        (socklen_t *)&clientAddrLen /* addrlen */);
    if (dfsclientSockDesc < 0)
    {
        perror("Accept failed\n");
        exit(1);
    }
    else
    {
        PRINT_DEBUG_MESSAGE("Accept success, clientSock : %d\n", dfsclientSockDesc);
     
        int handleReq = handleRequest(dfsclientSockDesc, fileDataBuffer);
        if (handleReq)
        {
            printf("handleRequest function failed\n");
        }
        
        close(dfsclientSockDesc);
    }
}

int readDFServerConfigFile(char *configFile, dfsParams *dfsServerParams)
{
    int retVal = -1;
    
    FILE *fp = fopen(configFile, "r");
    
    char *buffer;
    size_t numBytes = 120;
    char spaceDelimiter[] = " ";
    ssize_t bytesRead;
    int userCount = 0;
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    int countNumLinesRetVal = countNumLinesInFile(configFile, &numUsers);
    if (!countNumLinesRetVal)
    {
        buffer = (char *)malloc(numBytes*sizeof(char));
        
        if (fp)
        {
            while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
            {
                char *token;
                token = strtok(buffer, spaceDelimiter);
                
                strncpy(dfsServerParams->dfsUsersAndPasswords[userCount].userName, token, strlen(token));
                token = strtok(NULL, spaceDelimiter);
                strncpy(dfsServerParams->dfsUsersAndPasswords[userCount].password, token, strlen(token)-1);
                
                userCount++;
            }
            
            retVal = 0;
            fclose(fp);
        }
    }
    
    if (buffer)
        free(buffer);
    
    return retVal;
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

int countNumLinesInFile(char *fileName, int *numLines)
{
    FILE *fp = NULL;
    int retVal = -1;
    char c;
    int count = 0;
    
    fp = fopen(fileName, "r");
    
    /* Check if file exists */
    if (fp)
    {
        /* Extract characters from file and store in character c */
        for (c = getc(fp); c != EOF; c = getc(fp))
        {
            if (c == '\n') // Increment count if this character is newline
                count = count + 1;
        }
        
        *numLines = count;
        retVal = 0;
        
        /* Close the file */
        fclose(fp);
    }
    else
    {
        printf("File Open Failed\n");
    }
    
    return retVal;
}

void printDFServerConfigParams(dfsParams dfsServerParams)
{
    PRINT_DEBUG_MESSAGE("DFS Server Params:: \n");
    PRINT_DEBUG_MESSAGE("DFS directory: %s\n", dfsServerParams.dfsDirectory);
    PRINT_DEBUG_MESSAGE("DFS Port: %d\n", dfsServerParams.dfsPortNum);
    PRINT_DEBUG_MESSAGE("DFS Users and Password: \n");
    for (int i = 0; i < numUsers; i++ )
    {
        PRINT_DEBUG_MESSAGE("User: %s, Password: %s\n", dfsServerParams.dfsUsersAndPasswords[i].userName,
                                                        dfsServerParams.dfsUsersAndPasswords[i].password);
    }
}

int createSocketAndBind(struct sockaddr_in *dfsServerSockAddr, dfsParams dfsServerParams, int *dfsServerSockDesc)
{
    int retVal = -1;
    int serverSockfd = -1;
    
    memset(dfsServerSockAddr, 0, sizeof(struct sockaddr_in));
    
    printf("Port number used: %d\n", dfsServerParams.dfsPortNum);
    dfsServerSockAddr->sin_family = AF_INET;                            //address family
    dfsServerSockAddr->sin_port = htons(dfsServerParams.dfsPortNum);    //htons() sets the port # to network byte order
    dfsServerSockAddr->sin_addr.s_addr = INADDR_ANY;                    //supplies the IP address of the local machine
    
    if ((serverSockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Server socket creation failed (socket descriptor returned : %d)\n", serverSockfd);
    }
    else
    {
        printf("Server socket creation success (socket descriptor : %d)\n", serverSockfd);
        
        if (bind(serverSockfd, (struct sockaddr *)dfsServerSockAddr, sizeof(struct sockaddr_in)) < 0)
        {
            perror("Server socket bind failed\n");
            dfsServerSockAddr->sin_port=htons(0); /*   request a port number to be allocated
                                                       by bind */
            if (bind(serverSockfd, (struct sockaddr *)dfsServerSockAddr, sizeof(struct sockaddr_in)) < 0)
                perror("Server socket bind failed\n");
        }
        else
        {
            printf("Server socket bind success\n");
            *dfsServerSockDesc = serverSockfd;
            retVal = 0;
        }
    }
    
    return retVal;
}

int handleRequest(int clientSock, char *fileDataBuffer)
{
    int retVal = -1;
    char userName[50];
    char password[50];
    char command[50];
    
    memset(userName, '\0', sizeof(userName));
    memset(password, '\0', sizeof(password));
    memset(command, '\0', sizeof(command));
    
    ssize_t bytes_read = -1; /* Bytes successfully read */
    bytes_read = read(clientSock, /* read file descriptor*/
                      fileDataBuffer, /* buffer */
                      (FILE_DATA_MAX_LEN - 1) /* size of buffer */);
    
    if (bytes_read > 0)
    {
        printf("File Data Buffer content: %s\n", fileDataBuffer);
        
        extractReqParams(fileDataBuffer, userName, password, command);
        
        PRINT_DEBUG_MESSAGE("Username: %s, Password: %s, Command: %s\n",
                            userName, password, command);
        
        bool found = false;
        checkUsernameAndPassword(userName, password, &found);
        
        char responseMsg[50];
        if (found == true)
        {
            printf("Match found\n");
            
            sprintf(responseMsg, "Valid Username/Password");
            
            write(clientSock, responseMsg, strlen(responseMsg));
            
            if (strcmp(command, "LIST") == 0)
            {
                int listReqRetVal = handleListRequest(clientSock, fileDataBuffer);
                if (listReqRetVal != 0)
                {
                    printf("Handle List Request Failed\n");
                }
            }
            else if (strcmp(command, "GET") == 0)
            {
                int getReqRetVal = handleGetRequest(clientSock, fileDataBuffer);
                if (getReqRetVal != 0)
                {
                    printf("Handle Get Request Failed\n");
                }
            }
            else if (strcmp(command, "PUT") == 0)
            {
                int putReqRetVal = handlePutRequest(clientSock, fileDataBuffer);
                if (putReqRetVal != 0)
                {
                    printf("Handle Put Request Failed\n");
                }
            }
            else
            {
                printf("Invalid Command\n");
            }
            retVal = 0;
        }
        else
        {
            printf("Match not found\n");
            sprintf(responseMsg, "Invalid Username/Password. Please try again");
            
            write(clientSock, responseMsg, strlen(responseMsg));
            retVal = -1;
        }
    }
    else if (bytes_read == 0)
    {
        printf("File data read from socket failed\n");
        retVal = -1;
    }
    else
    {
        /* Do Nothing */
    }
    
    return retVal;
}

void extractReqParams(char *fileDataBuffer, char *userName, char *password, char *command)
{
    char spaceLimiter[] = " ";
    char colonLimiter[] = ":";
    
    char fileDataBufferCopy[1024];
    memset(fileDataBufferCopy, '\0', sizeof(fileDataBufferCopy));
    
    strcpy(fileDataBufferCopy, fileDataBuffer);
    
    char *usernameSubStr;
    
    usernameSubStr = strstr(fileDataBufferCopy, "username");
    
    char *passwordSubStr;
    
    passwordSubStr = strstr(fileDataBufferCopy, "password");
    
    char *commandSubStr;
    
    commandSubStr = strstr(fileDataBufferCopy, "command");
    
    char *token = strtok(usernameSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(userName, token2);
    }
    
    token = strtok(passwordSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(password, token2);
    }
    
    token = strtok(commandSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(command, token2);
    }
}

int handlePutRequest(int clientSock, char *fileDataBuffer)
{
    int retVal = -1;
    char userName[50];
    char password[50];
    char fileName[100];
    int fileMember1 = -1;
    int fileMember2 = -1;
    int fileSize1 = -1;
    int fileSize2 = -1;
    
    extractPutReqParams(fileDataBuffer, userName, password, fileName, &fileMember1,
                        &fileMember2, &fileSize1, &fileSize2);
    
    PRINT_DEBUG_MESSAGE("FileName: %s, FileSize: (%d, %d), FileMember: (%d, %d)\n",
                        fileName, fileSize1, fileSize2, fileMember1, fileMember2);
    
    char userDirPath[100];
    sprintf(userDirPath, "%s%s%s%s", "./", dfsServerParams.dfsDirectory, "/", userName);
    checkIfDirectoryExists(userDirPath);
    
    int readSize = 0;
    char fileName1[50], fileName2[50];
    memset(fileName1, '\0', sizeof(fileName1));
    memset(fileName2, '\0', sizeof(fileName2));
    
    sprintf(fileName1, "%s%s%s%s%s%s.%d", "./", dfsServerParams.dfsDirectory, "/", userName, "/", fileName, fileMember1);
    sprintf(fileName2, "%s%s%s%s%s%s.%d", "./", dfsServerParams.dfsDirectory, "/", userName, "/", fileName, fileMember2);
    
    //sprintf(fileName1, "%s%s%s%s%s%s%s.%d", "./", dfsServerParams.dfsDirectory, "/", userName, "/", ".", fileName, fileMember1);
    //sprintf(fileName2, "%s%s%s%s%s%s%s.%d", "./", dfsServerParams.dfsDirectory, "/", userName, "/", ".", fileName, fileMember2);
    
    printf("FileName1: %s, FileName2: %s\n", fileName1, fileName2);
    
    /* Check if file exists, if yes, delete the file */
    FILE *fpt1 = fopen(fileName1, "r");
    if (fpt1)
    {
        remove(fileName1);
        fclose(fpt1);
    }
    
    FILE *fpt2 = fopen(fileName2, "r");
    if (fpt2)
    {
        remove(fileName2);
        fclose(fpt2);
    }
    
    int sizeToRead = -1;
    FILE *fp = fopen(fileName1, "w");
    if (fp)
    {
        char receiveBuffer[1024];
        while (readSize < fileSize1)
        {
            sizeToRead = min(sizeof(receiveBuffer), (fileSize1 - readSize));
            memset(receiveBuffer, '\0', sizeof(receiveBuffer));
            read(clientSock, receiveBuffer, sizeToRead);
            //ssize_t rcvdBytes = recv(clientSock, receiveBuffer, sizeof(receiveBuffer), 0);
            fwrite(receiveBuffer, sizeof(char), sizeToRead, fp);
            
            readSize += sizeToRead;
            //printf("Received %d bytes out of %d bytes\n", readSize, fileSize);
        }
        printf("Received %d bytes out of %d bytes\n", readSize, fileSize1);
        fclose(fp);
    }
    
    readSize = 0;
    sizeToRead = -1;
    FILE *fp2 = fopen(fileName2, "w");
    if (fp2)
    {
        char receiveBuffer[1024];
        while (readSize < fileSize2)
        {
            sizeToRead = min(sizeof(receiveBuffer), (fileSize2 - readSize));
            memset(receiveBuffer, '\0', sizeof(receiveBuffer));
            read(clientSock, receiveBuffer, sizeToRead);
            //ssize_t rcvdBytes = recv(clientSock, receiveBuffer, sizeof(receiveBuffer), 0);
            fwrite(receiveBuffer, sizeof(char), sizeToRead, fp2);
            
            readSize += sizeToRead;
            //printf("Received %d bytes out of %d bytes\n", readSize, fileSize);
        }
        printf("Received %d bytes out of %d bytes\n", readSize, fileSize2);
        fclose(fp2);
    }
    
    retVal = 0;
    
    return retVal;
}

void extractPutReqParams(char *fileDataBuffer, char *userName, char *password, char *fileName,
                          int *fileMember1, int *fileMember2, int *fileSize1, int *fileSize2)
{
    char spaceLimiter[] = " ";
    char colonLimiter[] = ":";
    
    char *usernameSubStr;
    
    usernameSubStr = strstr(fileDataBuffer, "username");
    
    char *passwordSubStr;
    
    passwordSubStr = strstr(fileDataBuffer, "password");
    
    char *fileNameSubStr;
    
    fileNameSubStr = strstr(fileDataBuffer, "filename");
    
    char *fileMember1SubStr;
    
    fileMember1SubStr = strstr(fileDataBuffer, "fileMember1");
    
    char *fileMember2SubStr;
    
    fileMember2SubStr = strstr(fileDataBuffer, "fileMember2");
    
    char *fileSize1SubStr;
    
    fileSize1SubStr = strstr(fileDataBuffer, "filesize1");
    
    char *fileSize2SubStr;
    
    fileSize2SubStr = strstr(fileDataBuffer, "filesize2");
    
    char *token = strtok(usernameSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(userName, token2);
    }
    
    token = strtok(passwordSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(password, token2);
    }
    
    token = strtok(fileNameSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(fileName, token2);
    }
    
    token = strtok(fileMember1SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        *fileMember1 = atoi(token2);
    }
    
    token = strtok(fileMember2SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        *fileMember2 = atoi(token2);
    }
    
    token = strtok(fileSize1SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        *fileSize1 = atoi(token2);
    }
    
    token = strtok(fileSize2SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        *fileSize2 = atoi(token2);
    }
}

void checkUsernameAndPassword(char *userName, char *password, bool *found)
{
    *found = false;
    
    for (int i = 0; i < numUsers; i++)
    {
        if (strcmp(userName, dfsServerParams.dfsUsersAndPasswords[i].userName) == 0)
        {
            if (strcmp(password, dfsServerParams.dfsUsersAndPasswords[i].password) == 0)
            {
                *found = true;
            }
        }
    }
}

int handleGetRequest(int clientSock, char *fileDataBuffer)
{
    int retVal = -1;
    char userName[50];
    char password[50];
    char fileName[100];
    int fileMember1 = -1;
    int fileMember2 = -1;
    int filePart1Size = -1;
    int filePart2Size = -1;
    
    //printf("File Data Buffer content: %s\n", fileDataBuffer);
    
    extractGetReqParams(fileDataBuffer, userName, password, fileName);
    
    PRINT_DEBUG_MESSAGE("Username: %s, Password: %s, FileName: %s\n",
                        userName, password, fileName);
    
    char userDirPath[100];
    sprintf(userDirPath, "%s%s%s%s", "./", dfsServerParams.dfsDirectory, "/", userName);
    
    PRINT_DEBUG_MESSAGE("UserDirPath: %s\n", userDirPath);
    
    bool fileFound = false;
    checkForFileInDir(fileName, userDirPath, &fileFound, &fileMember1, &fileMember2);
    
    char file1Path[100];
    sprintf(file1Path, "%s%s%s.%d", userDirPath, "/", fileName, fileMember1);
    PRINT_DEBUG_MESSAGE("File1Path: %s\n", file1Path);
    
    FILE *fptr = fopen(file1Path, "r");
    if (fptr)
    {
        fseek(fptr, 0, SEEK_END);
        filePart1Size = (int)ftell(fptr);
        fseek(fptr, 0, SEEK_SET);
        fclose(fptr);
    }
    
    char file2Path[100];
    sprintf(file2Path, "%s%s%s.%d", userDirPath, "/", fileName, fileMember2);
    PRINT_DEBUG_MESSAGE("File1Path: %s\n", file2Path);
    
    FILE *fptr2 = fopen(file2Path, "r");
    if (fptr)
    {
        fseek(fptr, 0, SEEK_END);
        filePart2Size = (int)ftell(fptr2);
        fseek(fptr, 0, SEEK_SET);
        fclose(fptr2);
    }
    
    PRINT_DEBUG_MESSAGE("FileMembers: (%d, %d), FilePartSizes: (%d, %d)\n",
                        fileMember1, fileMember2, filePart1Size, filePart2Size);
    
    char responseMsg[100];
    memset(responseMsg, '\0', sizeof(responseMsg));
    if (fileFound == true)
    {
        printf("Match found\n");
        sprintf(responseMsg, "fileMember1:%d fileMember2:%d filePart1Size:%d filePart2Size:%d",
                fileMember1, fileMember2, filePart1Size, filePart2Size);
        
        write(clientSock, responseMsg, strlen(responseMsg));
        
        char reqBuffer[100];
        read(clientSock, reqBuffer, sizeof(reqBuffer));
        
        printf("Request Buffer: %s\n", reqBuffer);
        
        char filePart1Name[50];
        parseReqMsg(reqBuffer, filePart1Name);
        
        int sentSize = 0;
        char file1path[100];
        sprintf(file1path, "%s%s%s", userDirPath, "/", filePart1Name);
        
        int copySize = -1;
        FILE *fptr = fopen(file1path, "r");
        if (fptr)
        {
            char transmitBuffer[1024];
            while(sentSize < filePart1Size)
            {
                copySize = min(sizeof(transmitBuffer), (filePart1Size - sentSize));
                memset(transmitBuffer, 0, sizeof(transmitBuffer));
                fread(transmitBuffer, sizeof(char), copySize, fptr);
                
                write(clientSock, transmitBuffer, copySize);
                sentSize += copySize;
            }
            fclose(fptr);
        }
        
        memset(reqBuffer, 0, sizeof(reqBuffer));
        read(clientSock, reqBuffer, sizeof(reqBuffer));
        
        printf("Request Buffer: %s\n", reqBuffer);
        
        char filePart2Name[50];
        parseReqMsg(reqBuffer, filePart2Name);
        
        sentSize = 0;
        char file2path[100];
        sprintf(file2path, "%s%s%s", userDirPath, "/", filePart2Name);
        
        copySize = -1;
        fptr = fopen(file2path, "r");
        if (fptr)
        {
            char transmitBuffer[1024];
            while(sentSize < filePart2Size)
            {
                copySize = min(sizeof(transmitBuffer), (filePart2Size - sentSize));
                memset(transmitBuffer, 0, sizeof(transmitBuffer));
                fread(transmitBuffer, sizeof(char), copySize, fptr);
                
                write(clientSock, transmitBuffer, copySize);
                sentSize += copySize;
            }
            fclose(fptr);
        }
        
        retVal = 0;
    }
    else
    {
        printf("Match not found\n");
        sprintf(responseMsg, "Invalid Username/Password. Please try again");
        
        write(clientSock, responseMsg, strlen(responseMsg));
        retVal = -1;
    }
    
    return retVal;
}

void extractGetReqParams(char *fileDataBuffer, char *userName, char *password, char *fileName)
{
    char spaceLimiter[] = " ";
    char colonLimiter[] = ":";
    
    char *usernameSubStr;
    
    usernameSubStr = strstr(fileDataBuffer, "username");
    
    char *passwordSubStr;
    
    passwordSubStr = strstr(fileDataBuffer, "password");
    
    char *fileNameSubStr;
    
    fileNameSubStr = strstr(fileDataBuffer, "filename");
    
    char *token = strtok(usernameSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(userName, token2);
    }
    
    token = strtok(passwordSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(password, token2);
    }
    
    token = strtok(fileNameSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(fileName, token2);
    }
}

void checkForFileInDir(char *fileName, char *userDirPath, bool *fileFound,
                       int *fileMember1, int *fileMember2)
{
    DIR *d;
    struct dirent *dir;
    
    char dotDeLimiter[] = ".";
    
    *fileMember1 = 0;
    *fileMember2 = 0;
    
    d = opendir(userDirPath);
    printf("Looking for file %s\n", fileName);
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (strstr(dir->d_name, fileName))
            {
                printf("File: %s\n", dir->d_name);
                char filePartName[100];
                strcpy(filePartName, dir->d_name);
                
                char prevFileMemberToken[50];
                char *fileMemberToken = strtok(filePartName, dotDeLimiter);
                while (fileMemberToken != NULL)
                {
                    fileMemberToken = strtok(NULL, dotDeLimiter);
                    if (fileMemberToken != NULL)
                        strcpy(prevFileMemberToken, fileMemberToken);
                }
                
                if (*fileMember1 == 0)
                {
                    *fileMember1 = atoi(prevFileMemberToken);
                }
                else
                {
                    if (*fileMember2 == 0)
                    {
                        *fileMember2 = atoi(prevFileMemberToken);
                        *fileFound = true;
                    }
                }
            }
        }
        closedir(d);
    }
}

void parseReqMsg(char *reqBuffer, char *filePartName)
{
    char spaceDelimiter[] = " ";
    char *token = strtok(reqBuffer, spaceDelimiter);
    if (token != NULL)
    {
        token = strtok(NULL, spaceDelimiter);
        
        strcpy(filePartName, token);
    }
}

int handleListRequest(int clientSock, char *fileDataBuffer)
{
    int retVal = -1;
    char userName[50];
    char password[50];
    char fileList[5*1024];
    
    memset(fileList, '\0', sizeof(fileList));
    
    extractListReqParams(fileDataBuffer, userName, password);
    
    PRINT_DEBUG_MESSAGE("Username: %s, Password: %s\n",
                        userName, password);
    
    char responseMsg[1024];
    memset(responseMsg, '\0', sizeof(responseMsg));
    
    char dirPath[50];
    sprintf(dirPath, "%s%s", "./", dfsServerParams.dfsDirectory);
    listFilesInDir(dirPath, 0, fileList);
    
    /* Remove the trailing comma character at the end of fileList */
    
    if(fileList[strlen(fileList) - 1] == ',')
    {
        fileList[strlen(fileList) - 1] = '\0';
    }
    
    strcpy(responseMsg, fileList);
    write(clientSock, responseMsg, strlen(responseMsg));
    
    retVal = 0;
    
    return retVal;
}

void extractListReqParams(char *fileDataBuffer, char *userName, char *password)
{
    char spaceLimiter[] = " ";
    char colonLimiter[] = ":";
    
    char *usernameSubStr;
    
    usernameSubStr = strstr(fileDataBuffer, "username");
    
    char *passwordSubStr;
    
    passwordSubStr = strstr(fileDataBuffer, "password");
    
    char *token = strtok(usernameSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(userName, token2);
    }
    
    token = strtok(passwordSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(password, token2);
    }
}

void listFilesInDir(char *dirPath, int indent, char *fileList)
{
    DIR *dir;
    struct dirent *dirEnt;
    
    /* Checking for files in DFS server */
    if ((dir = opendir(dirPath)) != NULL)
    {
        while ((dirEnt = readdir(dir)) != NULL)
        {
            char fileName[50];
            memset(fileName, '\0', sizeof(fileName));
            //sprintf(fileName, "%s%s%s%s%s", dirPath, "/", dirEnt->d_name, ",", " ")
            if (dirEnt->d_type == DT_DIR)
            {
                sprintf(fileName, "%s%s%s%s", dirPath, "/", dirEnt->d_name, ",");
                strcat(fileList, fileName);
                char path[1024];
                if (strcmp(dirEnt->d_name, ".") == 0 || strcmp(dirEnt->d_name, "..") == 0)
                    continue;
                snprintf(path, sizeof(path), "%s//%s", dirPath, dirEnt->d_name);
                printf("%*s[%s]\n", indent, "", dirEnt->d_name);
                listFilesInDir(path, indent+2, fileList);
            }
            else
            {
                sprintf(fileName, "%s%s%s%s", dirPath, "/", dirEnt->d_name, ",");
                strcat(fileList, fileName);
                printf("%*s- %s\n", indent, "", dirEnt->d_name);
            }
        }
        closedir(dir);
    }
}
