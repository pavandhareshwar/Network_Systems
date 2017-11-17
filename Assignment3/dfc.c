#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>  //inet_addr
#include <unistd.h>     //write
#include <errno.h>
#include <fcntl.h>
#include <openssl/md5.h>

#include "dfc.h"

int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        printf("Usage: dfc <config_file_name>\n");
        exit(1);
    }
    
    char configFile[50];
    
    strcpy(configFile, argv[1]);
    
    int configFileRetVal = readDFClientConfigFile(configFile, &dfcConfigParams);
    if (!configFileRetVal)
    {
        printDFClientConfigParams(dfcConfigParams);
    }
    
    int fillServerSockRetVal = fillDFSServerSockAddrStruct(&dfs1ServerSockAddr, &dfs2ServerSockAddr,
                                                           &dfs3ServerSockAddr, &dfs4ServerSockAddr,
                                                           dfcConfigParams);
    
    if (fillServerSockRetVal)
    {
        PRINT_DEBUG_MESSAGE("fillDFSServerSockAddrStruct function failed\n");
    }
    
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    /*  Create a TCP server sockets */
    int createTcpSockRetVal = createDFSServerSockets();
    if (createTcpSockRetVal)
    {
        PRINT_DEBUG_MESSAGE("createDFSServerSockets function failed\n");
    }
    
    //char *file = "test_file.txt";
    //char *file = "1.txt";
    //char *file = "test_image.jpg";
    //char *file = "SampleImage2.jpg";
    //char *file =  "testFile.txt";
    
    char userInput[100];
    printf("Enter the command that the client needs to send to the server:\n");
    printf("1 : LIST\n");
    printf("2 : GET <filename> <subfolder>\n");
    printf("3 : PUT <filename> <subfolder>\n");
    printf("4 : MKDIR <subfolder>\n");
    printf("6 : unsupported\n");
    
    gets(userInput);
    
    printf("userInput: %s\n", userInput);
    
    char commandName[10];
    char fileName[100];
    char subfolder[100];
    
    memset(commandName, '\0', sizeof(commandName));
    memset(fileName, '\0', sizeof(fileName));
    memset(subfolder, '\0', sizeof(subfolder));
    
    char spaceDeLimiter[] = " ";
    char *token = strtok(userInput, spaceDeLimiter);
    
    if (token)
    {
        strcpy(commandName, token);
        
        token = strtok(NULL, spaceDeLimiter);
        if (token)
        {
            if ((strcmp(commandName, "GET") == 0) || (strcmp(commandName, "PUT") == 0))
            {
                strcpy(fileName, token);
            }
            else if ((strcmp(commandName, "LIST") == 0) || (strcmp(commandName, "MKDIR") == 0))
            {
                strcpy(subfolder, token);
            }
        }
        
        token = strtok(NULL, spaceDeLimiter);
        if (token)
        {
            if ((strcmp(commandName, "GET") == 0) || (strcmp(commandName, "PUT") == 0))
            {
                strcpy(subfolder, token);
            }
        }
    }
    
    if (strcmp(commandName, "LIST") == 0)
    {
        printf("Command: %s", commandName);
        if (*subfolder != '\0')
        {
            printf(" subFolder: %s\n", subfolder);
        }
        else
        {
            printf("\n");
        }
        
        memset(&xDfsServerFileList, '\0', sizeof(xDfsServerFileList));
        dfsServerFileListUserCount = 0;
        
        /*  TODO: List should only list files under the specified
         username folder. Change the code to do this instead.
         */
        int listFilesRetVal = listFilesFromDFSServers(subfolder);
        if (listFilesRetVal)
        {
            printf("listFileFromDFSServers function failed\n");
        }
        else
        {
            printf("listFileFromDFSServers success\n");
        }
    }
    else if (strcmp(commandName, "GET") == 0)
    {
        printf("Command: %s, fileName: %s", commandName, fileName);
        if (*subfolder != '\0')
        {
            printf(" subFolder: %s\n", subfolder);
        }
        else
        {
            printf("\n");
        }
        
        int getFilesRetVal = getFileFromDFSServers(fileName, subfolder);
        if (getFilesRetVal)
        {
            printf("getFilesFromDFSServers function failed\n");
        }
        else
        {
            printf("getFilesFromDFSServers success\n");
        }
    }
    else if (strcmp(commandName, "PUT") == 0)
    {
        printf("Command: %s, fileName: %s", commandName, fileName);
        if (*subfolder != '\0')
        {
            printf(" subFolder: %s\n", subfolder);
        }
        else
        {
            printf("\n");
        }
        
        int sendFilesRetVal = sendFilesToDFSServers(fileName, subfolder);
        if (sendFilesRetVal)
        {
            printf("sendFilesToDFSServers function failed\n");
        }
        else
        {
            printf("sendFilesToDFSServers success\n");
        }
    }
    else if (strcmp(commandName, "MKDIR") == 0)
    {
        printf("Command: %s, subFolder: %s", commandName, subfolder);
        int createSubFolderRetVal = createSubFolderonDFS(subfolder);
        if (createSubFolderRetVal)
        {
            printf("createSubFolderonDFS function failed\n");
        }
        else
        {
            printf("createSubFolderonDFS success\n");
        }
    }
    else
    {
        /* Do Nothing */
    }
    
    return 0;
}

int readDFClientConfigFile(char *configFileName, dfcParams *dfcConfigParams)
{
    
    FILE *fp = fopen(configFileName, "r");
    int retVal = -1;

    char *buffer;
    size_t numBytes = 120;
    char spaceDelimiter[] = " ";
    char colonDelimiter[] = ":";
    ssize_t bytesRead;
    
    buffer = (char *)malloc(numBytes*sizeof(char));
    
    if (fp)
    {
        while((bytesRead = getline(&buffer, &numBytes, fp)) != -1)
        {
            char *token;
            token = strtok(buffer, spaceDelimiter);
            
            if (strcmp(token, "Server") == 0)
            {
                token = strtok(NULL, spaceDelimiter);
                while (token != NULL)
                {
                    if (strcmp(token, "DFS1") == 0)
                    {
                        strcpy(dfcConfigParams->dfs1Params.dfsName, "DFS1");
                        token = strtok(NULL, spaceDelimiter);
                        if (token)
                        {
                            token = strtok(token, colonDelimiter);
                            strcpy(dfcConfigParams->dfs1Params.dfsIPAddress, token);
                            
                            token = strtok(NULL, colonDelimiter);
                            dfcConfigParams->dfs1Params.dfsPortNum = atoi(token);
                            break;
                        }
                    }
                    else if (strcmp(token, "DFS2") == 0)
                    {
                        strcpy(dfcConfigParams->dfs2Params.dfsName, "DFS2");
                        token = strtok(NULL, spaceDelimiter);
                        if (token)
                        {
                            token = strtok(token, colonDelimiter);
                            strcpy(dfcConfigParams->dfs2Params.dfsIPAddress, token);
                            
                            token = strtok(NULL, colonDelimiter);
                            dfcConfigParams->dfs2Params.dfsPortNum = atoi(token);
                            break;
                        }
                    }
                    else if (strcmp(token, "DFS3") == 0)
                    {
                        strcpy(dfcConfigParams->dfs3Params.dfsName, "DFS3");
                        token = strtok(NULL, spaceDelimiter);
                        if (token)
                        {
                            token = strtok(token, colonDelimiter);
                            strcpy(dfcConfigParams->dfs3Params.dfsIPAddress, token);
                            
                            token = strtok(NULL, colonDelimiter);
                            dfcConfigParams->dfs3Params.dfsPortNum = atoi(token);
                            break;
                        }
                    }
                    else if (strcmp(token, "DFS4") == 0)
                    {
                        strcpy(dfcConfigParams->dfs4Params.dfsName, "DFS4");
                        token = strtok(NULL, spaceDelimiter);
                        if (token)
                        {
                            token = strtok(token, colonDelimiter);
                            strcpy(dfcConfigParams->dfs4Params.dfsIPAddress, token);
                            
                            token = strtok(NULL, colonDelimiter);
                            dfcConfigParams->dfs4Params.dfsPortNum = atoi(token);
                            break;
                        }
                    }
                }
            }
            else if (strcmp(token, "Username:") == 0)
            {
                token = strtok(NULL, spaceDelimiter);
                strncpy(dfcConfigParams->userName, token, strlen(token)-1);
            }
            else if (strcmp(token, "Password:") == 0)
            {
                token = strtok(NULL, spaceDelimiter);
                strncpy(dfcConfigParams->password, token, strlen(token)-1);
            }
            else
            {
                /* Do Nothing */
            }
        }
        
        retVal = 0;
        fclose(fp);
    }
    
    if (buffer)
        free(buffer);
    
    return retVal;
}

void printDFClientConfigParams(dfcParams dfcConfigParams)
{
    PRINT_DEBUG_MESSAGE("DFS1 Parameters::");
    PRINT_DEBUG_MESSAGE("Name: %s, IP address: %s, Port: %d\n", dfcConfigParams.dfs1Params.dfsName,
                        dfcConfigParams.dfs1Params.dfsIPAddress, dfcConfigParams.dfs1Params.dfsPortNum);
    
    PRINT_DEBUG_MESSAGE("DFS2 Parameters::");
    PRINT_DEBUG_MESSAGE("Name: %s, IP address: %s, Port: %d\n", dfcConfigParams.dfs2Params.dfsName,
                        dfcConfigParams.dfs2Params.dfsIPAddress, dfcConfigParams.dfs2Params.dfsPortNum);
    
    PRINT_DEBUG_MESSAGE("DFS3 Parameters::");
    PRINT_DEBUG_MESSAGE("Name: %s, IP address: %s, Port: %d\n", dfcConfigParams.dfs3Params.dfsName,
                        dfcConfigParams.dfs3Params.dfsIPAddress, dfcConfigParams.dfs3Params.dfsPortNum);
    
    PRINT_DEBUG_MESSAGE("DFS4 Parameters::");
    PRINT_DEBUG_MESSAGE("Name: %s, IP address: %s, Port: %d\n", dfcConfigParams.dfs4Params.dfsName,
                        dfcConfigParams.dfs4Params.dfsIPAddress, dfcConfigParams.dfs4Params.dfsPortNum);
    
    PRINT_DEBUG_MESSAGE("Username: %s\n", dfcConfigParams.userName);
    
    PRINT_DEBUG_MESSAGE("Password: %s\n", dfcConfigParams.password);
}

int fillDFSServerSockAddrStruct(struct sockaddr_in *pDfs1ServerSockAddr, struct sockaddr_in *pDfs2ServerSockAddr,
                                struct sockaddr_in *pDfs3ServerSockAddr, struct sockaddr_in *pDfs4ServerSockAddr,
                                dfcParams dfcConfigParams)
{
    int retVal = -1;
    
    /* DFS1 */
    memset(pDfs1ServerSockAddr, 0, sizeof(struct sockaddr_in));
    
    /*  Define sockaddr_in structure for server */
    pDfs1ServerSockAddr->sin_family = AF_INET;    /* socket_family = IPv4 */
    pDfs1ServerSockAddr->sin_port = htons(dfcConfigParams.dfs1Params.dfsPortNum);  /* port */
    pDfs1ServerSockAddr->sin_addr.s_addr = INADDR_ANY; /* Receive packets destined to any of the available interfaces */
    
    /* DFS2 */
    memset(pDfs2ServerSockAddr, 0, sizeof(struct sockaddr_in));
    
    /*  Define sockaddr_in structure for server */
    pDfs2ServerSockAddr->sin_family = AF_INET;    /* socket_family = IPv4 */
    pDfs2ServerSockAddr->sin_port = htons(dfcConfigParams.dfs2Params.dfsPortNum);  /* port */
    pDfs2ServerSockAddr->sin_addr.s_addr = INADDR_ANY; /* Receive packets destined to any of the available interfaces */
    
    /* DFS3 */
    memset(pDfs3ServerSockAddr, 0, sizeof(struct sockaddr_in));
    
    /*  Define sockaddr_in structure for server */
    pDfs3ServerSockAddr->sin_family = AF_INET;    /* socket_family = IPv4 */
    pDfs3ServerSockAddr->sin_port = htons(dfcConfigParams.dfs3Params.dfsPortNum);  /* port */
    pDfs3ServerSockAddr->sin_addr.s_addr = INADDR_ANY; /* Receive packets destined to any of the available interfaces */
    
    /* DFS4 */
    memset(pDfs4ServerSockAddr, 0, sizeof(struct sockaddr_in));
    
    /*  Define sockaddr_in structure for server */
    pDfs4ServerSockAddr->sin_family = AF_INET;    /* socket_family = IPv4 */
    pDfs4ServerSockAddr->sin_port = htons(dfcConfigParams.dfs4Params.dfsPortNum);  /* port */
    pDfs4ServerSockAddr->sin_addr.s_addr = INADDR_ANY; /* Receive packets destined to any of the available interfaces */
    
    retVal = 0;
    return retVal;
}

int createDFSServerSockets(void)
{
    int retVal = -1;
    
    dfs1ServerSock = socket(AF_INET, /* socket_family = IPv4 */
                            SOCK_STREAM, /* socket_type = TCP */
                            0 /* Single protocol */);
    
    if (-1 == dfs1ServerSock)
    {
        printf("DFS1 Server socket creation failed\n");
    }
    else
    {
        printf("DFS1 Server socket successfully created\n");
        
        setsockopt(dfs1ServerSock, SOL_SOCKET, SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
        
        dfs2ServerSock = socket(AF_INET, /* socket_family = IPv4 */
                                SOCK_STREAM, /* socket_type = TCP */
                                0 /* Single protocol */);
        
        if (-1 == dfs2ServerSock)
        {
            printf("DFS2 Server socket creation failed\n");
        }
        else
        {
            printf("DFS2 Server socket successfully created\n");
            
            setsockopt(dfs2ServerSock, SOL_SOCKET, SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
            
            dfs3ServerSock = socket(AF_INET, /* socket_family = IPv4 */
                                    SOCK_STREAM, /* socket_type = TCP */
                                    0 /* Single protocol */);
            
            if (-1 == dfs3ServerSock)
            {
                printf("DFS3 Server socket creation failed\n");
            }
            else
            {
                printf("DFS3 Server socket successfully created\n");
                
                setsockopt(dfs3ServerSock, SOL_SOCKET, SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
                
                dfs4ServerSock = socket(AF_INET, /* socket_family = IPv4 */
                                        SOCK_STREAM, /* socket_type = TCP */
                                        0 /* Single protocol */);
                
                if (-1 == dfs4ServerSock)
                {
                    printf("DFS4 Server socket creation failed\n");
                }
                else
                {
                    printf("DFS4 Server socket successfully created\n");
                    
                    setsockopt(dfs4ServerSock, SOL_SOCKET, SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
                    
                    retVal = 0;
                }
            }
        }
    }
    
    return retVal;
}

int divideFiles(char *fileName, char *filePart1, char *filePart2, char *filePart3, char *filePart4)
{
    int retVal = -1;
    FILE *fp = fopen(fileName, "r");
    int fileSize = -1;
    int filePartSize = -1;
    
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        fileSize = (int)ftell(fp);
        fseek(fp, 0, SEEK_SET);
        
        filePartSize = fileSize/4;
        
        filePart1 = malloc(filePartSize*sizeof(char));
        if (filePart1)
        {
            fread(filePart1, sizeof(char), filePartSize, fp);
            fseek(fp, filePartSize, SEEK_SET);
            
            filePart2 = malloc(filePartSize*sizeof(char));
            if (filePart2)
            {
                fread(filePart2, sizeof(char), filePartSize, fp);
                fseek(fp, filePartSize, SEEK_CUR);
                
                filePart3 = malloc(filePartSize*sizeof(char));
                if (filePart3)
                {
                    fread(filePart3, sizeof(char), filePartSize, fp);
                    fseek(fp, filePartSize, SEEK_CUR);
                    
                    filePart4 = malloc(filePartSize*sizeof(char));
                    if (filePart4)
                    {
                        fread(filePart4, sizeof(char), filePartSize, fp);
                        fseek(fp, 0, SEEK_SET); /* Rewinding file to start */
                        retVal = 0;
                    }
                    else
                    {
                        printf("Malloc failed for filePart4\n");
                    }
                }
                else
                {
                    printf("Malloc failed for filePart3\n");
                }
            }
            else
            {
                printf("Malloc failed for filePart2\n");
            }
        }
        else
        {
            printf("Malloc failed for filePart1\n");
        }
        fclose(fp);
    }
    
    return retVal;
}

int sendFilesToDFSServers(char *fileName, char *subfolderName)
{
    int retVal = -1;
    int fileSize = -1;
    int filePartSize = -1;
    int filePartSize1 = -1;
    int filePartSize2 = -1;
    int filePartSize3 = -1;
    int filePartSize4 = -1;
    int xVal = -1;
    
    dfsFilePairMembers dfs1Members;
    dfsFilePairMembers dfs2Members;
    dfsFilePairMembers dfs3Members;
    dfsFilePairMembers dfs4Members;
    
    FILE *fp = fopen(fileName, "r");
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        fileSize = (int)ftell(fp);
        filePartSize = fileSize/4;
        printf("FileSize: %d, FilePartSize: %d\n", fileSize, filePartSize);
        fseek(fp, 0, SEEK_SET);
        fclose(fp);
    }
    
    filePartSize1 = filePartSize;
    filePartSize2 = filePartSize;
    filePartSize3 = filePartSize;
    if ((fileSize - (filePartSize*4)) != 0)
    {
        filePartSize4 = filePartSize + (fileSize - (filePartSize*4));
    }
    else
    {
        filePartSize4 = filePartSize;
    }
                                        
    printf("File Part Sizes:\n");
    printf("FilePart1 Size: %d\n", filePartSize1);
    printf("FilePart2 Size: %d\n", filePartSize2);
    printf("FilePart3 Size: %d\n", filePartSize3);
    printf("FilePart4 Size: %d\n", filePartSize4);
    
    int hashRetVal = calculateMD5Hash(fileName, &xVal);
    if (!hashRetVal)
    {
        
        decideFilePairs(xVal, &dfs1Members, &dfs2Members, &dfs3Members, &dfs4Members,
                        filePartSize1, filePartSize2, filePartSize3, filePartSize4);
        
        printFilePairs(dfs1Members, dfs2Members, dfs3Members, dfs4Members);
        
        char headerMessage[100];
        memset(headerMessage, '\0', sizeof(headerMessage));
        
        if (*subfolderName == '\0')
        {
            sprintf(headerMessage, "command:%s username:%s password:%s subfolderName:%s filename:%s",
                    "PUT", dfcConfigParams.userName, dfcConfigParams.password, "Nil", fileName);
        }
        else
        {
            sprintf(headerMessage, "command:%s username:%s password:%s subfolderName:%s filename:%s",
                    "PUT", dfcConfigParams.userName, dfcConfigParams.password, subfolderName, fileName);
        }
        
        /* Sending files to DFS1 */
        retVal = sendFileDataToDFSServer("DFS1", dfs1Members, fileName, headerMessage);

        /* Sending files to DFS2 */
        retVal = sendFileDataToDFSServer("DFS2", dfs2Members, fileName, headerMessage);
        
        /* Sending files to DFS3 */
        retVal = sendFileDataToDFSServer("DFS3", dfs3Members, fileName, headerMessage);
        
        /* Sending files to DFS4 */
        retVal = sendFileDataToDFSServer("DFS4", dfs4Members, fileName, headerMessage);
        
    }
    
    return retVal;
}

int calculateMD5Hash(char *filename, int *xVal)
{
    int retVal = -1;
    FILE *file_ptr;
    file_ptr = fopen(filename, "r");
    if (file_ptr)
    {
        int n;
        MD5_CTX c;
        char buf[512];
        ssize_t bytes;
        unsigned char out[MD5_DIGEST_LENGTH];
        
        MD5_Init(&c);
        do
        {
            bytes = fread(buf, 1, 512, file_ptr);
            MD5_Update(&c, buf, bytes);
        }while(bytes > 0);
        
        MD5_Final(out, &c);
        
        for(n = 0; n < MD5_DIGEST_LENGTH; n++)
        {
            printf("%02x", out[n]);
        }
        printf("\n");
        
        char md5AsString[100];
        char *pmd5AsString = &md5AsString[0];
        char md5CurByte[10];
        for(n = 0; n < MD5_DIGEST_LENGTH; n++)
        {
            sprintf(md5CurByte, "%02x", out[n]);
            strncpy(pmd5AsString, md5CurByte, strlen(md5CurByte));
            pmd5AsString += strlen(md5CurByte);
        }
        
        printf("md5AsString: %s\n", md5AsString);
        
        char md5lastbyte[10];
        sprintf(md5lastbyte, "%02x", out[MD5_DIGEST_LENGTH-1]);
        
        *xVal = (hex2int(md5AsString)) % 4;
        printf("md5AsInt = %d, xVal = %d\n", hex2int(md5AsString), *xVal);
        retVal = 0;
    }
    else
    {
        perror("Error opening file");
        fflush(stdout);
        retVal = -1;
    }
    
    return retVal;
}

uint32_t hex2int(char *hex)
{
    uint32_t val = 0;
    while (*hex)
    {
        /* get current character then increment */
        char byte = *hex++;
        /* transform hex character to the 4bit equivalent number, using the ascii table indexes */
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
        else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;
        /* shift 4 to make space for new digit, and add the 4 bits of the new digit */
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}

void decideFilePairs(int xVal, dfsFilePairMembers *dfs1Members, dfsFilePairMembers *dfs2Members,
                     dfsFilePairMembers *dfs3Members, dfsFilePairMembers *dfs4Members,
                     int filePart1Size, int filePart2Size, int filePart3Size, int filePart4Size)
{
    switch(xVal)
    {
        case 0:
            /* (DFS1, 1, 2), (DFS2, 2, 3), (DFS2, 3, 4), (DFS3, 4, 1) */
            dfs1Members->fileMember1 = 1;
            dfs1Members->fileMember2 = 2;
            dfs1Members->fileMember1Size = filePart1Size;
            dfs1Members->fileMember2Size = filePart2Size;
            
            dfs2Members->fileMember1 = 2;
            dfs2Members->fileMember2 = 3;
            dfs2Members->fileMember1Size = filePart2Size;
            dfs2Members->fileMember2Size = filePart3Size;
            
            dfs3Members->fileMember1 = 3;
            dfs3Members->fileMember2 = 4;
            dfs3Members->fileMember1Size = filePart3Size;
            dfs3Members->fileMember2Size = filePart4Size;
            
            dfs4Members->fileMember1 = 4;
            dfs4Members->fileMember2 = 1;
            dfs4Members->fileMember1Size = filePart4Size;
            dfs4Members->fileMember2Size = filePart1Size;
            break;
        case 1:
            /* (DFS1, 4, 1), (DFS2, 1, 2), (DFS2, 2, 3), (DFS3, 3, 4) */
            dfs1Members->fileMember1 = 4;
            dfs1Members->fileMember2 = 1;
            dfs1Members->fileMember1Size = filePart4Size;
            dfs1Members->fileMember2Size = filePart1Size;
            
            dfs2Members->fileMember1 = 1;
            dfs2Members->fileMember2 = 2;
            dfs2Members->fileMember1Size = filePart1Size;
            dfs2Members->fileMember2Size = filePart2Size;
            
            dfs3Members->fileMember1 = 2;
            dfs3Members->fileMember2 = 3;
            dfs3Members->fileMember1Size = filePart2Size;
            dfs3Members->fileMember2Size = filePart3Size;
            
            dfs4Members->fileMember1 = 3;
            dfs4Members->fileMember2 = 4;
            dfs4Members->fileMember1Size = filePart3Size;
            dfs4Members->fileMember2Size = filePart4Size;
            break;
        case 2:
            /* (DFS1, 3, 4), (DFS2, 4, 1), (DFS2, 1, 2), (DFS3, 2, 3) */
            dfs1Members->fileMember1 = 3;
            dfs1Members->fileMember2 = 4;
            dfs1Members->fileMember1Size = filePart3Size;
            dfs1Members->fileMember2Size = filePart4Size;
            
            dfs2Members->fileMember1 = 4;
            dfs2Members->fileMember2 = 1;
            dfs2Members->fileMember1Size = filePart4Size;
            dfs2Members->fileMember2Size = filePart1Size;
            
            dfs3Members->fileMember1 = 1;
            dfs3Members->fileMember2 = 2;
            dfs3Members->fileMember1Size = filePart1Size;
            dfs3Members->fileMember2Size = filePart2Size;
            
            dfs4Members->fileMember1 = 2;
            dfs4Members->fileMember2 = 3;
            dfs4Members->fileMember1Size = filePart2Size;
            dfs4Members->fileMember2Size = filePart3Size;
            break;
        case 3:
            /* (DFS1, 2, 3), (DFS2, 3, 4), (DFS2, 4, 1), (DFS3, 1, 2) */
            dfs1Members->fileMember1 = 2;
            dfs1Members->fileMember2 = 3;
            dfs1Members->fileMember1Size = filePart2Size;
            dfs1Members->fileMember2Size = filePart3Size;
            
            dfs2Members->fileMember1 = 3;
            dfs2Members->fileMember2 = 4;
            dfs2Members->fileMember1Size = filePart3Size;
            dfs2Members->fileMember2Size = filePart4Size;
            
            dfs3Members->fileMember1 = 4;
            dfs3Members->fileMember2 = 1;
            dfs3Members->fileMember1Size = filePart4Size;
            dfs3Members->fileMember2Size = filePart1Size;
            
            dfs4Members->fileMember1 = 1;
            dfs4Members->fileMember2 = 2;
            dfs4Members->fileMember1Size = filePart1Size;
            dfs4Members->fileMember2Size = filePart2Size;
            break;
        default:
            /* (DFS1, 1, 2), (DFS2, 2, 3), (DFS2, 3, 4), (DFS3, 4, 1) */
            dfs1Members->fileMember1 = 1;
            dfs1Members->fileMember2 = 2;
            dfs1Members->fileMember1Size = filePart1Size;
            dfs1Members->fileMember2Size = filePart2Size;
            
            dfs2Members->fileMember1 = 2;
            dfs2Members->fileMember2 = 3;
            dfs2Members->fileMember1Size = filePart2Size;
            dfs2Members->fileMember2Size = filePart3Size;
            
            dfs3Members->fileMember1 = 3;
            dfs3Members->fileMember2 = 4;
            dfs3Members->fileMember1Size = filePart3Size;
            dfs3Members->fileMember2Size = filePart4Size;
            
            dfs4Members->fileMember1 = 4;
            dfs4Members->fileMember2 = 1;
            dfs4Members->fileMember1Size = filePart4Size;
            dfs4Members->fileMember2Size = filePart1Size;
            break;
    }
}

void printFilePairs(dfsFilePairMembers dfs1Members, dfsFilePairMembers dfs2Members,
                    dfsFilePairMembers dfs3Members, dfsFilePairMembers dfs4Members)
{
    PRINT_DEBUG_MESSAGE("DFS File Pairs Info:\n");
    PRINT_DEBUG_MESSAGE("DFS1: (%d, %d)\n", dfs1Members.fileMember1, dfs1Members.fileMember2);
    PRINT_DEBUG_MESSAGE("DFS2: (%d, %d)\n", dfs2Members.fileMember1, dfs2Members.fileMember2);
    PRINT_DEBUG_MESSAGE("DFS3: (%d, %d)\n", dfs3Members.fileMember1, dfs3Members.fileMember2);
    PRINT_DEBUG_MESSAGE("DFS4: (%d, %d)\n", dfs4Members.fileMember1, dfs4Members.fileMember2);
}

int sendFileDataToDFSServer(char *dfsName, dfsFilePairMembers dfsMembers,
                            char *fileName, char *headerMsg)
{
    int retVal = -1;
    
    char headerMsgPlusFilePair[256];
    char filePairInfo[100];
    sprintf(filePairInfo, " fileMember1:%d fileMember2:%d filesize1:%d filesize2:%d",
            dfsMembers.fileMember1, dfsMembers.fileMember2,
            dfsMembers.fileMember1Size, dfsMembers.fileMember2Size);
    strcpy(headerMsgPlusFilePair, headerMsg);
    strcat(headerMsgPlusFilePair, filePairInfo);
    
    printf("headerMsgPlusFilePair: %s\n", headerMsgPlusFilePair);
    
    if (strcmp(dfsName, "DFS1") == 0)
    {
        retVal = sendFileToDFSServer(fileName, headerMsgPlusFilePair, dfs1ServerSock,
                            dfs1ServerSockAddr, dfsMembers.fileMember1,
                            dfsMembers.fileMember1Size, dfsMembers.fileMember2Size);
    }
    else if (strcmp(dfsName, "DFS2") == 0)
    {
        retVal = sendFileToDFSServer(fileName, headerMsgPlusFilePair, dfs2ServerSock,
                            dfs2ServerSockAddr, dfsMembers.fileMember1,
                            dfsMembers.fileMember1Size, dfsMembers.fileMember2Size);
    }
    else if (strcmp(dfsName, "DFS3") == 0)
    {
        retVal = sendFileToDFSServer(fileName, headerMsgPlusFilePair, dfs3ServerSock,
                            dfs3ServerSockAddr, dfsMembers.fileMember1,
                            dfsMembers.fileMember1Size, dfsMembers.fileMember2Size);
    }
    else if (strcmp(dfsName, "DFS4") == 0)
    {
        retVal = sendFileToDFSServer(fileName, headerMsgPlusFilePair, dfs4ServerSock,
                            dfs4ServerSockAddr, dfsMembers.fileMember1,
                            dfsMembers.fileMember1Size, dfsMembers.fileMember2Size);
    }
    else
    {
        /* Do Nothing */
    }
    
    return retVal;
}

int sendFileToDFSServer(char *fileName, char *headerMsg, int dfsServerSock,
                        struct sockaddr_in dfsServerSockAddr, int firstMember,
                        int fileSize1ToSend, int fileSize2ToSend)
{
    int retVal = -1;
    ssize_t n;
    
    int connRetVal = connect(dfsServerSock, (struct sockaddr *)&dfsServerSockAddr, sizeof(dfsServerSockAddr));
    if (connRetVal == 0)
    {
        /* send the message line to the server */
        n = write(dfsServerSock, headerMsg, strlen(headerMsg));
        if (n < 0)
        {
            perror("ERROR writing to socket");
        }
        else
        {
            char responseBuffer[100];
            memset(responseBuffer, '\0', sizeof(responseBuffer));
            read(dfsServerSock, responseBuffer, sizeof(responseBuffer));
            printf("responseBuffer: %s\n", responseBuffer);
            
            if (strstr(responseBuffer, "Valid"))
            {
                int sentSize = 0;
                char transmitBuffer[1024];
                FILE *fp = fopen(fileName, "r");
                if (fp)
                {
                    switch(firstMember)
                    {
                        case 1:
                            /* Do Nothing */
                            break;
                        case 2:
                            fseek(fp, min(fileSize1ToSend, fileSize2ToSend), SEEK_SET);
                            break;
                        case 3:
                            fseek(fp, 2*min(fileSize1ToSend, fileSize2ToSend), SEEK_SET);
                            break;
                        case 4:
                            fseek(fp, 3*min(fileSize1ToSend, fileSize2ToSend), SEEK_SET);
                            break;
                    }
                    
                    while (sentSize < fileSize1ToSend)
                    {
                        int copysize = min(sizeof(transmitBuffer), (fileSize1ToSend - sentSize));
                        memset(transmitBuffer, '\0', sizeof(transmitBuffer));
                        fread(transmitBuffer, sizeof(char), copysize, fp);
                        
#ifdef ENCRYPTION
                        char * encrypted = xorencrypt(transmitBuffer, dfcConfigParams.password);
                        
                        n = write(dfsServerSock, encrypted, copysize);
                        if (n < 0)
                            perror("ERROR writing to socket");
                        
                        free(encrypted);
#else
                        
                        /* TODO: Encrypt the data here before sending */
                        n = write(dfsServerSock, transmitBuffer, copysize);
                        if (n < 0)
                            perror("ERROR writing to socket");
#endif
                        
                        sentSize += copysize;
                        //printf("Sent %d bytes out of %d bytes\n", sentSize, fileSizeToSend);
                    }
                    printf("Sent %d bytes out of %d bytes\n", sentSize, fileSize1ToSend);
                    
                    if (firstMember == 4)
                    {
                        fseek(fp, 0, SEEK_SET);
                    }
                    
                    int copysize = -1;
                    sentSize = 0;
                    while (sentSize < fileSize2ToSend)
                    {
                        copysize = min(sizeof(transmitBuffer), (fileSize2ToSend-sentSize));
                        memset(transmitBuffer, '\0', sizeof(transmitBuffer));
                        fread(transmitBuffer, sizeof(char), copysize, fp);
                        
#ifdef ENCRYPTION
                        char * encrypted = xorencrypt(transmitBuffer, dfcConfigParams.password);
                        
                        n = write(dfsServerSock, encrypted, copysize);
                        if (n < 0)
                            perror("ERROR writing to socket");
                        
                        free(encrypted);
#else
                        
                        /* TODO: Encrypt the data here before sending */
                        n = write(dfsServerSock, transmitBuffer, copysize);
                        if (n < 0)
                            perror("ERROR writing to socket");
#endif
                        
                        n = write(dfsServerSock, transmitBuffer, copysize);
                        if (n < 0)
                            perror("ERROR writing to socket");
                        
                        sentSize += copysize;
                        //printf("Sent %d bytes out of %d bytes\n", sentSize, fileSizeToSend);
                    }
                    printf("Sent %d bytes out of %d bytes\n", sentSize, fileSize2ToSend);
                    retVal = 0;
                }
            }
            else if (strstr(responseBuffer, "Invalid") == 0)
            {
                printf("Invalid Username/Password. Please try again!!\n");
                retVal = -1;
            }
            else
            {
                /* Do nothing */
            }
        }
    }
    else
    {
        perror("ERROR connecting");
    }
    
    return retVal;
}

char * xorencrypt(char * message, char * key)
{
    size_t messagelen = strlen(message);
    size_t keylen = strlen(key);
    
    char * encrypted = malloc(messagelen+1);
    
    memset(encrypted, '\0', (messagelen+1));
    
    int i;
    for(i = 0; i < messagelen; i++) {
        encrypted[i] = message[i] ^ key[i % keylen];
    }
    encrypted[messagelen] = '\0';
    
    return encrypted;
}

int getFileFromDFSServers(char *fileName, char *subfolderName)
{
    int retVal = -1;
    
    dfsFilePairMembers dfs1Members;
    dfsFilePairMembers dfs2Members;
    dfsFilePairMembers dfs3Members;
    dfsFilePairMembers dfs4Members;
    
    intializeDfsFilePairMembers(&dfs1Members, &dfs2Members, &dfs3Members, &dfs4Members);
    
    char headerMessage[100];
    if (*subfolderName == '\0')
    {
        sprintf(headerMessage, "username:%s password:%s command:%s filename:%s subfolder:%s",
                dfcConfigParams.userName, dfcConfigParams.password, "GET", fileName, "Nil");
    }
    else
    {
        sprintf(headerMessage, "username:%s password:%s command:%s filename:%s subfolder:%s",
                dfcConfigParams.userName, dfcConfigParams.password, "GET", fileName, subfolderName);
    }
    
    
    /* Getting files from DFS1 */
    retVal = getFileInfoFromDFSServers("DFS1", &dfs1Members, fileName, headerMessage);
   
    /* Getting files from DFS2 */
    retVal =  getFileInfoFromDFSServers("DFS2", &dfs2Members, fileName, headerMessage);
    
    /* Getting files from DFS3 */
    retVal =  getFileInfoFromDFSServers("DFS3", &dfs3Members, fileName, headerMessage);
    
    /* Getting files from DFS4 */
    retVal =  getFileInfoFromDFSServers("DFS4", &dfs4Members, fileName, headerMessage);
    
    bool canBeCombined = checkIfFilesCanBeCombined(dfs1Members, dfs2Members, dfs3Members, dfs4Members);
    
    if (canBeCombined == true)
    {
        combineFiles(fileName);
        retVal = 0;
    }
    else
    {
        printf("File is Incomplete\n");
        retVal = 0;
    }
    
    return retVal;
}

void intializeDfsFilePairMembers(dfsFilePairMembers *dfs1Members, dfsFilePairMembers *dfs2Members,
                                 dfsFilePairMembers *dfs3Members, dfsFilePairMembers *dfs4Members)
{
    dfs1Members->fileMember1 = -1;
    dfs1Members->fileMember2 = -1;
    
    dfs2Members->fileMember1 = -1;
    dfs2Members->fileMember2 = -1;
    
    dfs3Members->fileMember1 = -1;
    dfs3Members->fileMember2 = -1;
    
    dfs4Members->fileMember1 = -1;
    dfs4Members->fileMember2 = -1;
}

int getFileInfoFromDFSServers(char *dfsName, dfsFilePairMembers *dfsMembers, char *fileName, char *headerMsg)
{
    int retVal = -1;
    int filePart1SizeDFS1 = -1;
    int filePart2SizeDFS1 = -1;
    
    int filePart1SizeDFS2 = -1;
    int filePart2SizeDFS2 = -1;
    
    int filePart1SizeDFS3 = -1;
    int filePart2SizeDFS3 = -1;
    
    int filePart1SizeDFS4 = -1;
    int filePart2SizeDFS4 = -1;
    
    if (strcmp(dfsName, "DFS1") == 0)
    {
        retVal = getFileInfoFromDFSServer(headerMsg, dfs1ServerSock, dfs1ServerSockAddr, dfsMembers,
                                 &filePart1SizeDFS1, &filePart2SizeDFS1);
        if (!retVal)
        {
            retVal = requestFileFromDFSServer(dfs1ServerSock, dfs1ServerSockAddr, dfsMembers, fileName,
                                 filePart1SizeDFS1, filePart2SizeDFS1);
        }
    }
    else if (strcmp(dfsName, "DFS2") == 0)
    {
        retVal = getFileInfoFromDFSServer(headerMsg, dfs2ServerSock, dfs2ServerSockAddr, dfsMembers,
                                 &filePart1SizeDFS2, &filePart2SizeDFS2);
        
        if (!retVal)
        {
            retVal = requestFileFromDFSServer(dfs2ServerSock, dfs2ServerSockAddr, dfsMembers, fileName,
                                 filePart1SizeDFS2, filePart2SizeDFS2);
        }
    }
    else if (strcmp(dfsName, "DFS3") == 0)
    {
        retVal = getFileInfoFromDFSServer(headerMsg, dfs3ServerSock, dfs3ServerSockAddr, dfsMembers,
                                 &filePart1SizeDFS3, &filePart2SizeDFS3);
        
        if (!retVal)
        {
            retVal = requestFileFromDFSServer(dfs3ServerSock, dfs3ServerSockAddr, dfsMembers, fileName,
                                 filePart1SizeDFS3, filePart2SizeDFS3);
        }
    }
    else if (strcmp(dfsName, "DFS4") == 0)
    {
        retVal = getFileInfoFromDFSServer(headerMsg, dfs4ServerSock, dfs4ServerSockAddr, dfsMembers,
                                 &filePart1SizeDFS4, &filePart2SizeDFS4);
        
        if (!retVal)
        {
            retVal = requestFileFromDFSServer(dfs4ServerSock, dfs4ServerSockAddr, dfsMembers, fileName,
                                 filePart1SizeDFS4, filePart2SizeDFS4);
        }
    }
    else
    {
        /* Do Nothing */
    }
    
    return retVal;
}

int getFileInfoFromDFSServer(char *headerMsg, int dfsServerSock, struct sockaddr_in dfsServerSockAddr,
                             dfsFilePairMembers *dfsMembers, int *filePart1Size, int *filePart2Size)
{
    int retVal = -1;
    ssize_t n;
    
    int connRetVal = connect(dfsServerSock, (struct sockaddr *)&dfsServerSockAddr, sizeof(dfsServerSockAddr));
    if (connRetVal == 0)
    {
        /* send the message line to the server */
        n = write(dfsServerSock, headerMsg, strlen(headerMsg));
        if (n < 0)
        {
            perror("ERROR writing to socket");
        }
        else
        {
            char responseBuffer[512];
            memset(responseBuffer, '\0', sizeof(responseBuffer));
            read(dfsServerSock, responseBuffer, sizeof(responseBuffer));
            printf("responseBuffer: %s\n", responseBuffer);
            
            if (strstr(responseBuffer, "Valid"))
            {
                memset(responseBuffer, '\0', sizeof(responseBuffer));
                read(dfsServerSock, responseBuffer, sizeof(responseBuffer));
                printf("responseBuffer: %s\n", responseBuffer);
                
                parseGetResponseMsg(responseBuffer, dfsMembers, filePart1Size, filePart2Size);
                
                retVal = 0;
            }
        }
    }
    else
    {
        perror("ERROR connecting");
    }
    
    return retVal;
}

void parseGetResponseMsg(char *responseBuffer, dfsFilePairMembers *dfsMembers,
                         int *filePart1Size, int *filePart2Size)
{
    char spaceLimiter[] = " ";
    char colonLimiter[] = ":";
    
    char *file1SubStr = strstr(responseBuffer, "file1");
    
    char *file2SubStr = strstr(responseBuffer, "file2");
    
    char *fileMem1SubStr = strstr(responseBuffer, "fileMember1");
    
    char *fileMem2SubStr = strstr(responseBuffer, "fileMember2");
    
    char *filePart1SizeSubStr = strstr(responseBuffer, "filePart1Size");
    
    char *filePart2SizeSubStr = strstr(responseBuffer, "filePart2Size");
    
    char *token = strtok(file1SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(dfsMembers->fileMember1Name, token2);
    }
    
    token = strtok(file2SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        strcpy(dfsMembers->fileMember2Name, token2);
    }
    
    token = strtok(fileMem1SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        dfsMembers->fileMember1 = atoi(token2);
    }
    
    token = strtok(fileMem2SubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        dfsMembers->fileMember2 = atoi(token2);
    }
    
    token = strtok(filePart1SizeSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        *filePart1Size = atoi(token2);
    }
    
    token = strtok(filePart2SizeSubStr, spaceLimiter);
    if (token)
    {
        char *token2 = strtok(token, colonLimiter);
        token2 = strtok(NULL, colonLimiter);
        *filePart2Size = atoi(token2);
    }
}

int requestFileFromDFSServer(int dfsServerSock, struct sockaddr_in dfsServerSockAddr,
                             dfsFilePairMembers *dfsMembers, char *fileName,
                             int filePart1Size, int filePart2Size)
{
    int retVal = -1;
    ssize_t n;
    FILE *fptr = NULL;
    FILE *fptr2 = NULL;
    char command[100];
    memset(command, '\0', sizeof(command));
    
    //sprintf(command, "%s %s.%d", "GET", fileName, dfsMembers->fileMember1);
    sprintf(command, "%s %s", "GET", dfsMembers->fileMember1Name);
    
    /* send the message line to the server */
    n = write(dfsServerSock, command, strlen(command));
    if (n < 0)
    {
        perror("ERROR writing to socket");
    }
    else
    {
        char filePart1Name[50];
        //sprintf(filePart1Name, "%s.%d", fileName, dfsMembers->fileMember1);
        strcpy(filePart1Name, dfsMembers->fileMember1Name);
        
        if (filePart1Name[0] == '.')
        {
            memcpy(filePart1Name, filePart1Name+1, strlen(filePart1Name));
        }
        
        printf("filePart1Name:%s\n", filePart1Name);
        
        int readSize = 0;
        int sizeToRead = -1;
        
        fptr = fopen(filePart1Name, "w");
        if (fptr)
        {
            char receiveBuffer[1024];
            while(readSize < filePart1Size)
            {
                sizeToRead = min(sizeof(receiveBuffer), (filePart1Size - readSize));
                memset(receiveBuffer, '\0', sizeof(receiveBuffer));
                read(dfsServerSock, receiveBuffer, sizeToRead);
                
#ifdef ENCRYPTION
                char * decrypted = xorencrypt(receiveBuffer, dfcConfigParams.password);
                
                fwrite(decrypted, sizeof(char), (sizeToRead-1), fptr);
                
                free(decrypted);
#else
                
                fwrite(receiveBuffer, sizeof(char), sizeToRead, fptr);
#endif
                
                //ssize_t rcvdBytes = recv(clientSock, receiveBuffer, sizeof(receiveBuffer), 0);
                
                readSize += sizeToRead;
            }
            printf("Received %d out of %d bytes\n", readSize, filePart1Size);
            fclose(fptr);
        }
        
        memset(command, '\0', sizeof(command));
        //sprintf(command, "%s %s.%d", "GET", fileName, dfsMembers->fileMember2);
        sprintf(command, "%s %s", "GET", dfsMembers->fileMember2Name);
        
        /* send the message line to the server */
        n = write(dfsServerSock, command, strlen(command));
        if (n < 0)
        {
            perror("ERROR writing to socket");
        }
        else
        {
            char filePart2Name[50];
            //sprintf(filePart2Name, "%s.%d", fileName, dfsMembers->fileMember2);
            strcpy(filePart2Name, dfsMembers->fileMember2Name);
            
            if (filePart2Name[0] == '.')
            {
                memcpy(filePart2Name, filePart2Name+1, strlen(filePart2Name));
            }
            
            printf("filePart2Name:%s\n", filePart2Name);
            
            readSize = 0;
            sizeToRead = -1;
            
            fptr2 = fopen(filePart2Name, "w");
            if (fptr2)
            {
                char receiveBuffer[1024];
                while(readSize < filePart2Size)
                {
                    sizeToRead = min(sizeof(receiveBuffer), (filePart2Size - readSize));
                    memset(receiveBuffer, '\0', sizeof(receiveBuffer));
                    read(dfsServerSock, receiveBuffer, sizeToRead);
                    
#ifdef ENCRYPTION
                    char * decrypted = xorencrypt(receiveBuffer, dfcConfigParams.password);
                    
                    fwrite(decrypted, sizeof(char), (sizeToRead-1), fptr);
                    
                    free(decrypted);
#else
                    
                    fwrite(receiveBuffer, sizeof(char), sizeToRead, fptr);
#endif
                    
                    //ssize_t rcvdBytes = recv(clientSock, receiveBuffer, sizeof(receiveBuffer), 0);
                    
                    readSize += sizeToRead;
                }
                printf("Received %d out of %d bytes\n", readSize, filePart2Size);
                fclose(fptr2);
            }
            retVal = 0;
        }
    }
    return retVal;
}

bool checkIfFilesCanBeCombined(dfsFilePairMembers dfs1Members, dfsFilePairMembers dfs2Members,
                               dfsFilePairMembers dfs3Members, dfsFilePairMembers dfs4Members)
{
    bool canBeCombined = false;
    
    if (((dfs1Members.fileMember1 == -1) && (dfs1Members.fileMember2 == -1) &&
         (dfs2Members.fileMember1 != -1) && (dfs2Members.fileMember2 != -1) &&
         (dfs3Members.fileMember1 != -1) && (dfs3Members.fileMember2 != -1) &&
         (dfs4Members.fileMember1 != -1) && (dfs4Members.fileMember2 != -1))
        || ((dfs2Members.fileMember1 == -1) && (dfs2Members.fileMember2 == -1) &&
           (dfs1Members.fileMember1 != -1) && (dfs1Members.fileMember2 != -1) &&
           (dfs3Members.fileMember1 != -1) && (dfs3Members.fileMember2 != -1) &&
           (dfs4Members.fileMember1 != -1) && (dfs4Members.fileMember2 != -1))
        || ((dfs3Members.fileMember1 == -1) && (dfs3Members.fileMember2 == -1) &&
            (dfs1Members.fileMember1 != -1) && (dfs1Members.fileMember2 != -1) &&
            (dfs2Members.fileMember1 != -1) && (dfs2Members.fileMember2 != -1) &&
            (dfs4Members.fileMember1 != -1) && (dfs4Members.fileMember2 != -1))
        || ((dfs4Members.fileMember1 == -1) && (dfs4Members.fileMember2 == -1) &&
            (dfs1Members.fileMember1 != -1) && (dfs1Members.fileMember2 != -1) &&
            (dfs2Members.fileMember1 != -1) && (dfs2Members.fileMember2 != -1) &&
            (dfs3Members.fileMember1 != -1) && (dfs3Members.fileMember2 != -1))
        || ((dfs1Members.fileMember1 != -1) && (dfs1Members.fileMember2 != -1) &&
            (dfs2Members.fileMember1 != -1) && (dfs2Members.fileMember2 != -1) &&
            (dfs3Members.fileMember1 != -1) && (dfs3Members.fileMember2 != -1) &&
            (dfs4Members.fileMember1 != -1) && (dfs4Members.fileMember2 != -1)))
    {
        canBeCombined = true;
    }
    
    return canBeCombined;
}

void combineFiles(char *fileName)
{
    /*  Take the pieces that we got from all the DFS's and
        combine them into one file
     */
    char filePart1Path[50];
    char filePart2Path[50];
    char filePart3Path[50];
    char filePart4Path[50];
    int filePartNum = 1;
    
    FILE *fpCheck = fopen(fileName, "r");
    if (fpCheck)
    {
        printf("File %s exists. Deleting the file\n", fileName);
        remove(fileName);
        fclose(fpCheck);
    }
    
    FILE *fpWrite = fopen(fileName, "a");
    
    if (fpWrite)
    {
        sprintf(filePart1Path, "%s%s.%d", "./", fileName, filePartNum);
        combineIndividualFiles(fpWrite, filePart1Path);
        
        filePartNum++;
        
        sprintf(filePart2Path, "%s%s.%d", "./", fileName, filePartNum);
        combineIndividualFiles(fpWrite, filePart2Path);
        
        filePartNum++;
        
        sprintf(filePart3Path, "%s%s.%d", "./", fileName, filePartNum);
        combineIndividualFiles(fpWrite, filePart3Path);
        
        filePartNum++;
        
        sprintf(filePart4Path, "%s%s.%d", "./", fileName, filePartNum);
        combineIndividualFiles(fpWrite, filePart4Path);
        
        fclose(fpWrite);
    }
}

void combineIndividualFiles(FILE *fpWrite, char *filePartPath)
{
    int filePartSize = -1;
    char tempBuffer[1024];
    FILE *fpRead = fopen(filePartPath, "r");
    if (fpRead)
    {
        fseek(fpRead, 0, SEEK_END);
        filePartSize = (int)ftell(fpRead);
        fseek(fpRead, 0, SEEK_SET);
        
        printf("filePartPath: %s, size: %d\n", filePartPath, filePartSize);
        
        int readSize = 0;
        
        while(readSize < filePartSize)
        {
            memset(tempBuffer, '\0', sizeof(tempBuffer));
            int copySize = min(sizeof(tempBuffer), (filePartSize - readSize));
            fread(tempBuffer, sizeof(char), copySize, fpRead);
            readSize += copySize;
            
            fwrite(tempBuffer, sizeof(char), copySize, fpWrite);
        }
        fclose(fpRead);
    }
}

int listFilesFromDFSServers(char *subfolderName)
{
    int retVal = -1;
    char fileListDFSServer1[1024];
    char fileListDFSServer2[1024];
    char fileListDFSServer3[1024];
    char fileListDFSServer4[1024];
    
    memset(fileListDFSServer1, '\0', sizeof(fileListDFSServer1));
    memset(fileListDFSServer2, '\0', sizeof(fileListDFSServer2));
    memset(fileListDFSServer3, '\0', sizeof(fileListDFSServer3));
    memset(fileListDFSServer4, '\0', sizeof(fileListDFSServer4));
    
    char headerMessage[100];
    if (*subfolderName == '\0')
    {
        sprintf(headerMessage, "command:%s username:%s password:%s subfolder:%s",
                "LIST", dfcConfigParams.userName, dfcConfigParams.password, "Nil");
    }
    else
    {
        sprintf(headerMessage, "command:%s username:%s password:%s subfolder:%s",
                "LIST", dfcConfigParams.userName, dfcConfigParams.password, subfolderName);
    }
    
    /* Getting files from DFS1 */
    listFilesFromIndividualDFSServer("DFS1", headerMessage, fileListDFSServer1);

    //printf("DFS Server1 Files:\n");
    //printDFSServerFileList(fileListDFSServer1);
    
    /* Getting files from DFS2 */
    listFilesFromIndividualDFSServer("DFS2", headerMessage, fileListDFSServer2);
    
    //printf("DFS Server2 Files:\n");
    //printDFSServerFileList(fileListDFSServer2);
    
    /* Getting files from DFS3 */
    listFilesFromIndividualDFSServer("DFS3", headerMessage, fileListDFSServer3);
    
    //printf("DFS Server3 Files:\n");
    //printDFSServerFileList(fileListDFSServer3);
    
    /* Getting files from DFS4 */
    listFilesFromIndividualDFSServer("DFS4", headerMessage, fileListDFSServer4);
    
    //printf("DFS Server4 Files:\n");
    //printDFSServerFileList(fileListDFSServer4);
    
    findFilesFromDFSServerFileList(fileListDFSServer1, fileListDFSServer2,
                                   fileListDFSServer3, fileListDFSServer4);
    
    retVal = 0;
    
    return retVal;
}

int listFilesFromIndividualDFSServer(char *dfsName, char *headerMsg, char *fileListBuffer)
{
    int retVal = -1;
    
    if (strcmp(dfsName, "DFS1") == 0)
    {
        int retVal = listAllFilesFromDFSServer(dfs1ServerSock, dfs1ServerSockAddr, headerMsg, fileListBuffer);
        if (retVal)
        {
            printf("SubFolder doesn't exist on DFS1\n");
        }
    }
    else if (strcmp(dfsName, "DFS2") == 0)
    {
        int retVal = listAllFilesFromDFSServer(dfs2ServerSock, dfs2ServerSockAddr, headerMsg, fileListBuffer);
        if (retVal)
        {
            printf("SubFolder doesn't exist on DFS2\n");
        }
    }
    else if (strcmp(dfsName, "DFS3") == 0)
    {
        int retVal = listAllFilesFromDFSServer(dfs3ServerSock, dfs3ServerSockAddr, headerMsg, fileListBuffer);
        if (retVal)
        {
            printf("SubFolder doesn't exist on DFS3\n");
        }
    }
    else if (strcmp(dfsName, "DFS4") == 0)
    {
        int retVal = listAllFilesFromDFSServer(dfs4ServerSock, dfs4ServerSockAddr, headerMsg, fileListBuffer);
        if (retVal)
        {
            printf("SubFolder doesn't exist on DFS4\n");
        }
    }
    else
    {
        /* Do Nothing */
    }
    
    return retVal;
}

int listAllFilesFromDFSServer(int dfsServerSock, struct sockaddr_in dfsServerSockAddr,
                              char *headerMsg, char *fileListBuffer)
{
    int retVal = -1;
    ssize_t n;
    
    int connRetVal = connect(dfsServerSock, (struct sockaddr *)&dfsServerSockAddr, sizeof(dfsServerSockAddr));
    if (connRetVal == 0)
    {
        /* send the message line to the server */
        n = write(dfsServerSock, headerMsg, strlen(headerMsg));
        if (n < 0)
        {
            perror("ERROR writing to socket");
        }
        else
        {
            char responseBuffer[100];
            memset(responseBuffer, '\0', sizeof(responseBuffer));
            read(dfsServerSock, responseBuffer, sizeof(responseBuffer));
            //printf("responseBuffer: %s\n", responseBuffer);
            
            if (strstr(responseBuffer, "Valid"))
            {
                read(dfsServerSock, fileListBuffer, 1024);
                if (strstr(fileListBuffer, "Error:"))
                {
                    retVal = -1;
                }
                else
                {
                    retVal = 0;
                }
            }
        }
    }
    else if (errno == ETIMEDOUT)
    {
        printf("Connection timed out\n");
    }
    else
    {
        perror("ERROR connecting");
    }
    
    return retVal;
}

void printDFSServerFileList(char *fileListBuffer)
{
    char commaDelimiter[] = ",";
    char fileListBufferCopy[1024];
    strcpy(fileListBufferCopy, fileListBuffer);
    char *token = strtok(fileListBufferCopy, commaDelimiter);
    
    while(token != NULL)
    {
        PRINT_DEBUG_MESSAGE("%s\n", token);
        token = strtok(NULL, commaDelimiter);
    }
}

void findFilesFromDFSServerFileList(char *fileListDFSServer1, char *fileListDFSServer2,
                                    char *fileListDFSServer3, char *fileListDFSServer4)
{
    char    commaDeLimiter[] = ",";
    int     dfsServerFileListFileCount[MAX_USER_FOLDERS];
    char    dfsServerFilesPerUser[MAX_USER_FOLDERS][MAX_FILE_COUNT][100];
    
    memset(dfsServerFileListFileCount, '\0', sizeof(dfsServerFileListFileCount));
    for (int i = 0; i < MAX_USER_FOLDERS; i++)
    {
        memset(dfsServerFilesPerUser[i], '\0', sizeof(dfsServerFilesPerUser[i]));
    }
    
    /* DFS Server 1 */
    char dfsServer1FileList[512];
    memset(dfsServer1FileList, '\0', sizeof(dfsServer1FileList));
    
    findFilesFromIndividualDFSServerFileList(fileListDFSServer1, dfsServer1FileList);
    printf("DFS Server 1 FileList: {%s}\n", dfsServer1FileList);
    
    /* DFS Server 2 */
    char dfsServer2FileList[512];
    memset(dfsServer2FileList, '\0', sizeof(dfsServer2FileList));
    
    findFilesFromIndividualDFSServerFileList(fileListDFSServer2, dfsServer2FileList);
    printf("DFS Server 2 FileList: {%s}\n", dfsServer2FileList);
    
    /* DFS Server 3 */
    char dfsServer3FileList[512];
    memset(dfsServer3FileList, '\0', sizeof(dfsServer3FileList));
    
    findFilesFromIndividualDFSServerFileList(fileListDFSServer3, dfsServer3FileList);
    printf("DFS Server 3 FileList: {%s}\n", dfsServer3FileList);
    
    /* DFS Server 4 */
    char dfsServer4FileList[512];
    memset(dfsServer4FileList, '\0', sizeof(dfsServer4FileList));
    
    findFilesFromIndividualDFSServerFileList(fileListDFSServer4, dfsServer4FileList);
    printf("DFS Server 4 FileList: {%s}\n", dfsServer4FileList);
    
    filldfsServerFileListInClient(dfsServer1FileList);
    
    filldfsServerFileListInClient(dfsServer2FileList);
    
    filldfsServerFileListInClient(dfsServer3FileList);
    
    filldfsServerFileListInClient(dfsServer4FileList);
    
    for (int i = 0; i < dfsServerFileListUserCount; i++)
    {
        int fileCountPerUser = 0;
        int length = (int)strlen(xDfsServerFileList.userFileList[i]);
        if (xDfsServerFileList.userFileList[i][length-1] == ',')
        {
            xDfsServerFileList.userFileList[i][length-1] = '\0';
        }
        
        char userFileListCopy[1024];
        memset(userFileListCopy, '\0', sizeof(userFileListCopy));
        strcpy(userFileListCopy, xDfsServerFileList.userFileList[i]);
        
        char *endStr;
        char *token = strtok_r(userFileListCopy, commaDeLimiter, &endStr);
        while (token != NULL)
        {
            *(token + strlen(token)-1) = '\0';
            *(token + strlen(token)-1) = '\0';
            
            bool fileMatchFound = false;
            if (strstr(xDfsServerFileList.userFileNames[i], token) != NULL)
            {
                fileMatchFound = true;
            }
            
            if (fileMatchFound == false)
            {
                char fileName[50];
                memset(fileName, '\0', sizeof(fileName));
                sprintf(fileName, "%s%s", token, ",");
                strcat(xDfsServerFileList.userFileNames[i], fileName);
                dfsServerFileListFileCount[i]++;
                strcpy(dfsServerFilesPerUser[i][fileCountPerUser], fileName);
                
                int len = (int)strlen(dfsServerFilesPerUser[i][fileCountPerUser]);
                if (dfsServerFilesPerUser[i][fileCountPerUser][len-1] == ',')
                {
                    dfsServerFilesPerUser[i][fileCountPerUser][len-1] = '\0';
                }
                fileCountPerUser++;
            }
            
            token = strtok_r(NULL, commaDeLimiter, &endStr);
        }
        PRINT_DEBUG_MESSAGE("dfsServerFileListFileCount[%d]: %d\n", i, dfsServerFileListFileCount[i]);
    }

    printf("================================================================\n");
    
    for (int i = 0; i < dfsServerFileListUserCount; i++)
    {
        int length = (int)strlen(xDfsServerFileList.userFileNames[i]);
        if (xDfsServerFileList.userFileNames[i][length-1] == ',')
        {
            xDfsServerFileList.userFileNames[i][length-1] = '\0';
        }
        
        //printf("%d -- Userfolder: %s, FileList: %s, FileNames: %s\n", i, xDfsServerFileList.userFolder[i],
        //       xDfsServerFileList.userFileList[i], xDfsServerFileList.userFileNames[i]);
        
        bool complete = false;
        char fileName1ToTest[100];
        char fileName2ToTest[100];
        char fileName3ToTest[100];
        char fileName4ToTest[100];
        for (int j = 0; j < dfsServerFileListFileCount[i]; j++)
        {
            memset(fileName1ToTest, '\0', sizeof(fileName1ToTest));
            memset(fileName2ToTest, '\0', sizeof(fileName2ToTest));
            memset(fileName3ToTest, '\0', sizeof(fileName3ToTest));
            memset(fileName4ToTest, '\0', sizeof(fileName4ToTest));
            
            sprintf(fileName1ToTest, "%s.%d", dfsServerFilesPerUser[i][j], 1);
            sprintf(fileName2ToTest, "%s.%d", dfsServerFilesPerUser[i][j], 2);
            sprintf(fileName3ToTest, "%s.%d", dfsServerFilesPerUser[i][j], 3);
            sprintf(fileName4ToTest, "%s.%d", dfsServerFilesPerUser[i][j], 4);
            
            if (strstr(xDfsServerFileList.userFileList[i], fileName1ToTest))
            {
                if (strstr(xDfsServerFileList.userFileList[i], fileName2ToTest))
                {
                    if (strstr(xDfsServerFileList.userFileList[i], fileName3ToTest))
                    {
                        if (strstr(xDfsServerFileList.userFileList[i], fileName4ToTest))
                        {
                            printf("%s/%s --> Complete\n", xDfsServerFileList.userFolder[i], dfsServerFilesPerUser[i][j]);
                            complete = true;
                        }
                    }
                }
                
            }
            if (complete == false)
            {
                printf("%s/%s --> Incomplete\n", xDfsServerFileList.userFolder[i], dfsServerFilesPerUser[i][j]);
            }
        }
    }
    printf("================================================================\n");
}

void filldfsServerFileListInClient(char *dfsServerFileList)
{
    char commaDeLimiter[] = ",";
    char doubleSlashDeLimiter[] = "//";
    
    char *endStr;
    char *token = strtok_r(dfsServerFileList, commaDeLimiter, &endStr);
    while(token != NULL)
    {
        char tokenCopy[100];
        memset(tokenCopy, '\0', sizeof(tokenCopy));
        strcpy(tokenCopy, token);
        
        bool matchFound = false;
        int matchedUserFolderIndex = -1;
        char *token2 = strstr(tokenCopy, doubleSlashDeLimiter);
        if (token2 != NULL)
        {
            char *token3 = strtok(tokenCopy, doubleSlashDeLimiter);
            if (token3)
            {
                for (int i = 0; i < MAX_USER_FOLDERS; i++)
                {
                    if (strcmp(xDfsServerFileList.userFolder[i], token3) == 0)
                    {
                        matchFound = true;
                        matchedUserFolderIndex = i;
                        //printf("Match found\n");
                        break;
                    }
                }
                
                token3 = strtok(NULL, doubleSlashDeLimiter);
                if (*token3 == '.')
                {
                    memcpy(token3, token3+1, strlen(token3));
                }
                
                if (matchFound == false)
                {
                    printf("No match found\n");
                    strcpy(xDfsServerFileList.userFolder[dfsServerFileListUserCount], tokenCopy);
                    
                    dfsServerFileListUserCount++;
                
                    char fileListEntry[50];
                    memset(fileListEntry, '\0', sizeof(fileListEntry));
                    sprintf(fileListEntry, "%s%s", token3, ",");
                    strcat(xDfsServerFileList.userFileList[dfsServerFileListUserCount], fileListEntry);
                }
                else
                {
                    char fileListEntry[50];
                    memset(fileListEntry, '\0', sizeof(fileListEntry));
                    sprintf(fileListEntry, "%s%s", token3, ",");
                    strcat(xDfsServerFileList.userFileList[matchedUserFolderIndex], fileListEntry);
                }
            }
        }
        else
        {
            if (dfsServerFileListUserCount == 0)
            {
                dfsServerFileListUserCount = 1;
            }
            if (*(tokenCopy) == '.')
            {
                memcpy(tokenCopy, tokenCopy+1, strlen(tokenCopy));
            }
            
            char fileListEntry[50];
            memset(fileListEntry, '\0', sizeof(fileListEntry));
            sprintf(fileListEntry, "%s%s", tokenCopy, ",");
            strcat(xDfsServerFileList.userFileList[0], fileListEntry);
        }
        
        token = strtok_r(NULL, commaDeLimiter, &endStr);
    }
    strcpy(xDfsServerFileList.userFolder[0], ".");
}

void findFilesFromIndividualDFSServerFileList(char *fileListDFSServer, char *dfsServerFileList)
{
    char commaDelimiter[] = ",";
    char doubleSlashDelimiter[] = "//";
    
    char fileListDFSServerCopy[1024];
    memset(fileListDFSServerCopy, '\0', sizeof(fileListDFSServerCopy));
    strcpy(fileListDFSServerCopy, fileListDFSServer);
    
    char *endStr;
    char *token = strtok_r(fileListDFSServerCopy, commaDelimiter, &endStr);
    
    while(token != NULL)
    {
        char *subStr = strstr(token, doubleSlashDelimiter);
        if (subStr != NULL)
        {
            memcpy(subStr, subStr+2, strlen(subStr));
            
            int length = (int)strlen(subStr);

            if ((*(subStr+length-1) == '.' && *(subStr+length-2) == '/') ||
                (*(subStr+length-1) == '.' && *(subStr+length-2) == '.' && *(subStr+length-3) == '/'))
            {
                continue;
            }
            
            char fileName[100];
            memset(fileName, '\0', sizeof(fileName));
#if 0
            if (*subStr != '.')
            {
                /* There is a username specific subfolder */
                char tokenCopy[100];
                memset(tokenCopy, '\0', sizeof(tokenCopy));
                strcpy(tokenCopy, token);
                char *token2 = strstr(tokenCopy, doubleSlashDelimiter);
                printf("token2: %s\n", token2);
                if (token2)
                {
                    memcpy(token2, token2+2, strlen(subStr));
                        
                    sprintf(fileName, "%s%s", token2, ",");
                    strcat(dfsServerFileList, fileName);
                }
            }
            else
#endif
            {
                sprintf(fileName, "%s%s", subStr, ",");
                strcat(dfsServerFileList, fileName);
            }
        }
        token = strtok_r(NULL, commaDelimiter, &endStr);
    }
    
    /* Removing the trailing space and comma character */
    if(dfsServerFileList[strlen(dfsServerFileList) - 1] == ',')
    {
        dfsServerFileList[strlen(dfsServerFileList) - 1] = '\0';
    }
}

int createSubFolderonDFS(char *subfolder)
{
    char headerMessage[200];
    int retVal = -1;
    
    sprintf(headerMessage, "command:%s username:%s password:%s subfolder:%s",
            "MKDIR", dfcConfigParams.userName, dfcConfigParams.password, subfolder);
    
    /* Creating subfolder on DFS1 */
    retVal = createSubFolderOnIndDFSServers("DFS1", headerMessage, dfs1ServerSock, dfs1ServerSockAddr);
    
    /* Creating subfolder on DFS2 */
    retVal = createSubFolderOnIndDFSServers("DFS2", headerMessage, dfs2ServerSock, dfs2ServerSockAddr);
    
    /* Creating subfolder on DFS3 */
    retVal = createSubFolderOnIndDFSServers("DFS3", headerMessage, dfs3ServerSock, dfs3ServerSockAddr);
    
    /* Creating subfolder on DFS4 */
    retVal = createSubFolderOnIndDFSServers("DFS4", headerMessage, dfs4ServerSock, dfs4ServerSockAddr);
    
    return retVal;
}


int createSubFolderOnIndDFSServers(char *dfsName, char *headerMsg, int dfsServerSock,
                                   struct sockaddr_in dfsServerSockAddr)
{
    int retVal = -1;
    ssize_t n;
    int connRetVal = connect(dfsServerSock, (struct sockaddr *)&dfsServerSockAddr, sizeof(dfsServerSockAddr));
    if (connRetVal == 0)
    {
        /* send the message line to the server */
        n = write(dfsServerSock, headerMsg, strlen(headerMsg));
        if (n < 0)
        {
            perror("ERROR writing to socket");
        }
        else
        {
            char responseBuffer[100];
            memset(responseBuffer, '\0', sizeof(responseBuffer));
            read(dfsServerSock, responseBuffer, sizeof(responseBuffer));
            printf("responseBuffer: %s\n", responseBuffer);
            retVal = 0;
        }
    }
    else
    {
        perror("ERROR connecting");
    }
    
    return retVal;
}
