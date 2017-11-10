#ifndef _DFS_H_
#define _DFS_H_

/*  ----------------------------------------------------------------
    Macros
    ----------------------------------------------------------------
 */

#define MAX_USERS_ALLOWED           (10)
#define LISTEN_SYSCALL_BACKLOG      (10)
#define FILE_DATA_MAX_LEN           (1024)

#define min(a,b)                    ((a) < (b) ? (a) : (b))

#define PRINT_DEBUG_MESSAGES        (1)

#ifdef PRINT_DEBUG_MESSAGES
#define PRINT_DEBUG_MESSAGE(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( false )
#else
#define PRINT_DEBUG_MESSAGE(...) do{ } while ( false )
#endif

/*  ----------------------------------------------------------------
     Globals
    ----------------------------------------------------------------
 */
int numUsers;

/*  ----------------------------------------------------------------
     Structure/Enumerations
    ----------------------------------------------------------------
 */
typedef struct _dfsUserList_
{
    char    userName[50];
    char    password[50];
}dfsUserList;

typedef struct _dfsParams_
{
    char        dfsDirectory[100];
    int         dfsPortNum;
    dfsUserList dfsUsersAndPasswords[MAX_USERS_ALLOWED];
}dfsParams;

dfsParams   dfsServerParams;

/*  ----------------------------------------------------------------
     Function Prototypes
    ----------------------------------------------------------------
 */

static int readDFServerConfigFile(char *configFile, dfsParams *dfsServerParams);
void checkIfDirectoryExists(char *dirName);
static void printDFServerConfigParams(dfsParams dfsServerParams);
static int countNumLinesInFile(char *fileName, int *numLines);
static int createSocketAndBind(struct sockaddr_in *dfsServerSockAddr, dfsParams dfsServerParams, int *dfsServerSockDesc);
static int handleRequest(int clientSock, char *fileDataBuffer);
static void extractReqParams(char *fileDataBuffer, char *userName, char *password, char *command);
static int handlePutRequest(int clientSock, char *fileDataBuffer);
static void checkUsernameAndPassword(char *userName, char *password, bool *found);
static void extractPutReqParams(char *fileDataBuffer, char *userName, char *password, char *fileName,
                                int *fileMember1, int *fileMember2, int *fileSize1, int *fileSize2);

static int handleGetRequest(int clientSock, char *fileDataBuffer);
static void extractGetReqParams(char *fileDataBuffer, char *userName, char *password, char *fileName);
static void checkForFileInDir(char *fileName, char *userDirPath, bool *fileFound,
                              int *fileMember1, int *fileMember2);
static void parseReqMsg(char *reqBuffer, char *filePartName);

static int handleListRequest(int clientSock, char *fileDataBuffer);
static void listFilesInDir(char *dirPath, int indent, char *fileList);
static void extractListReqParams(char *fileDataBuffer, char *userName, char *password);

#endif

