#ifndef _DFC_H_
#define _DFC_H_

/*  ----------------------------------------------------------------
     Macros
    ----------------------------------------------------------------
 */

#define min(a,b)                    ((a) < (b) ? (a) : (b))
#define MAX_USER_FOLDERS            (10)
#define MAX_FILE_COUNT              (50)
#define ENCRYPTION                  (1)

//#define PRINT_DEBUG_MESSAGES        (1)

#ifdef PRINT_DEBUG_MESSAGES
#define PRINT_DEBUG_MESSAGE(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( false )
#else
#define PRINT_DEBUG_MESSAGE(...) do{ } while ( false )
#endif

/*  ----------------------------------------------------------------
     Structure/Enumerations
    ----------------------------------------------------------------
 */

typedef struct _dfsParams_
{
    char        dfsName[20];
    char        dfsIPAddress[50];
    int         dfsPortNum;
}dfsParams;

typedef struct _dfcParams_
{
    dfsParams   dfs1Params;
    dfsParams   dfs2Params;
    dfsParams   dfs3Params;
    dfsParams   dfs4Params;
    char        userName[50];
    char        password[50];
}dfcParams;

typedef struct _dfsFilePairMembers_
{
    char        fileMember1Name[100];
    char        fileMember2Name[100];
    int         fileMember1;
    int         fileMember2;
    int         fileMember1Size;
    int         fileMember2Size;
}dfsFilePairMembers;

typedef struct _dfsFileList_
{
    char        userFolder[MAX_USER_FOLDERS][50];
    char        userFileList[MAX_USER_FOLDERS][1024];
    char        userFileNames[MAX_FILE_COUNT][50];
}dfsFileList;

typedef struct _dfsFilePartsRecvd_
{
    bool        dfsFilePart1;
    bool        dfsFilePart2;
    bool        dfsFilePart3;
    bool        dfsFilePart4;
}dfsFilePartsRecvd;

/*  ----------------------------------------------------------------
     Globals
    ----------------------------------------------------------------
 */

/* DFS server sockets */
int dfs1ServerSock = -1;
int dfs2ServerSock = -1;
int dfs3ServerSock = -1;
int dfs4ServerSock = -1;

/*  sockaddr_in structure for socket information about client and server */
struct sockaddr_in dfs1ServerSockAddr;
struct sockaddr_in dfs2ServerSockAddr;
struct sockaddr_in dfs3ServerSockAddr;
struct sockaddr_in dfs4ServerSockAddr;

struct timeval timeout;

dfcParams           dfcConfigParams;
dfsFileList         xDfsServerFileList;
int                 dfsServerFileListUserCount;
dfsFilePartsRecvd   dfsFilePartsRcvdFromDFSServers;

/*  ----------------------------------------------------------------
     Function Prototypes
    ----------------------------------------------------------------
 */
static int readDFClientConfigFile(char *configFileName, dfcParams *dfcConfigParams);
static void printDFClientConfigParams(dfcParams dfcConfigParams);
static int fillDFSServerSockAddrStruct(struct sockaddr_in *pDfs1ServerSockAddr, struct sockaddr_in *pDfs2ServerSockAddr,
                                struct sockaddr_in *pDfs3ServerSockAddr, struct sockaddr_in *pDfs4ServerSockAddr,
                                dfcParams dfcConfigParams);
static int createDFSServerSockets(void);

static int divideFiles(char *fileName, char *filePart1, char *filePart2, char *filePart3, char *filePart4);

static int sendFilesToDFSServers(char *fileName, char *subfolderName);

static int sendFileDataToDFSServer(char *dfsName, dfsFilePairMembers dfsMembers, char *fileName, char *headerMsg);
static int calculateMD5Hash(char *filename, int *xVal);
static uint32_t hex2int(char *hex);
//static void decideFilePairs(int xVal, dfsFilePairMembers *df1Members, dfsFilePairMembers *df2Members,
//                            dfsFilePairMembers *df3Members, dfsFilePairMembers *df4Members);
static void decideFilePairs(int xVal, dfsFilePairMembers *dfs1Members, dfsFilePairMembers *dfs2Members,
                            dfsFilePairMembers *dfs3Members, dfsFilePairMembers *dfs4Members,
                            int filePart1Size, int filePart2Size, int filePart3Size, int filePart4Size);
static void printFilePairs(dfsFilePairMembers dfs1Members, dfsFilePairMembers dfs2Members,
                           dfsFilePairMembers dfs3Members, dfsFilePairMembers dfs4Members);
static int sendFileToDFSServer(char *fileName, char *headerMsg, int dfsServerSock,
                               struct sockaddr_in dfsServerSockAddr, int firstMember,
                               int fileSize1ToSend, int fileSize2ToSend);
static void fillFileSizeInfoInHeader(int xVal, char *headerMessage1, char *headerMessage2,
                                     char *headerMessage3, char *headerMessage4, int filePartSize1,
                                     int filePartSize2, int filePartSize3, int filePartSize4);

static void intializeDfsFilePairMembers(dfsFilePairMembers *dfs1Members, dfsFilePairMembers *dfs2Members,
                                        dfsFilePairMembers *dfs3Members, dfsFilePairMembers *dfs4Members);
//void xorencryptdecrypt(char *message, char *key);
static void xorencryptdecrypt(char *input, char *output, int messageLen, char *key);

static int getFileFromDFSServers(char *fileName, char *subfolderName);
static int getFileInfoFromDFSServers(char *dfsName, dfsFilePairMembers *dfsMembers, char *fileName, char *headerMsg);
static int getFileInfoFromDFSServer(char *headerMsg, int dfsServerSock, struct sockaddr_in dfsServerSockAddr,
                                    dfsFilePairMembers *dfsMembers, int *filePart1Size, int *filePart2Size);
static void parseGetResponseMsg(char *responseBuffer, dfsFilePairMembers *dfsMembers,
                                int *filePart1Size, int *filePart2Size);
static int requestFileFromDFSServer(int dfsServerSock, struct sockaddr_in dfsServerSockAddr,
                                    dfsFilePairMembers *dfsMembers, char *fileName,
                                    int filePart1Size, int filePart2Size);
static bool checkIfFilesCanBeCombined(dfsFilePairMembers dfs1Members, dfsFilePairMembers dfs2Members,
                                      dfsFilePairMembers dfs3Members, dfsFilePairMembers dfs4Members);
static void combineFiles(char *fileName);
void combineIndividualFiles(FILE *fpWrite, char *filePartPath);

static int listFilesFromDFSServers(char *subfolderName);
static int listFilesFromIndividualDFSServer(char *dfsName, char *headerMsg, char *fileListBuffer);
static int listAllFilesFromDFSServer(int dfsServerSock, struct sockaddr_in dfsServerSockAddr,
                                     char *headerMsg, char *fileListBuffer);
static void printDFSServerFileList(char *fileListBuffer);
static void findFilesFromDFSServerFileList(char *fileListDFSServer1, char *fileListDFSServer2,
                                           char *fileListDFSServer3, char *fileListDFSServer4);
static void findFilesFromIndividualDFSServerFileList(char *fileListDFSServer, char *dfsServerFileList);
static void filldfsServerFileListInClient(char *dfsServerFileList);

static int createSubFolderonDFS(char *subfolder);
static int createSubFolderOnIndDFSServers(char *dfsName, char *headerMsg, int dfsServerSock,
                                          struct sockaddr_in dfsServerSockAddr);

static void fillFileRequestBooleans(dfsFilePairMembers *dfsMembers, bool *pRequestFile1, bool *pRequestFile2);

static int connectWithTimeOut(int dfsSocket, struct sockaddr_in dfsServerSockAddr);

#endif
