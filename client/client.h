#ifndef _CLIENT_H
#define _CLIENT_H

//! \file client.h
//! \authors Douglas Healy (u16018100)
//! \authors Llewellyn Moyse (u15100708)
//! \authors Mohamed Ameen Omar (u16055323)
//! \date 2019/02/14
//! \brief Client program able to establish an SSL connection to a specified server
//! \version 1.0
//! \copyright Copyright &copy; 2019 - EHN410 Group 7


//--------------------------------------------------------------
// User includes
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


//--------------------------------------------------------------
// Defines

//! Buffer size used when writing to server
#define WRITE_BUFFER_SIZE   4096

//! Buffer size used when reading from server
#define READ_BUFFER_SIZE    1024
#define HTTP_DELIM          "\r\n"
#define HTTP_SPACE          " "
#define HTTP_CONTENT_TYPE   "Content-Type:"
#define HTTP_CONTENT_LEGNTH "Content-Length:"

// it is defined at compile time (in the makefile) so check first if
// it has been defined otherwise assign it a default value

//! Download path where client will download the specified file to, this can be defined at compile time
#ifndef HTTP_DOWNLOAD_PATH
#define HTTP_DOWNLOAD_PATH  "downloads"
#endif

#define COLOUR_RED   "\x1B[31m"
#define COLOUR_GRN   "\x1B[32m"
#define COLOUR_YEL   "\x1B[33m"
#define COLOUR_BLU   "\x1B[34m"
#define COLOUR_MAG   "\x1B[35m"
#define COLOUR_CYN   "\x1B[36m"
#define COLOUR_WHT   "\x1B[37m"
#define COLOUR_RESET "\x1B[0m"

#ifndef TRUE
#define TRUE    (1 == 1)
#define FALSE   (1 == 0)
#endif

#ifdef DEBUG
#define trace(f_, args...)      printf("%s(%d): "f_"\r\n", __FUNCTION__, __LINE__, ##args)
#define _printf(f_, args...)    printf("%s(%d): "f_"\r\n", __FUNCTION__, __LINE__, ##args)
#else
//! \def A debugging macro, which prints the function name which it was called from
//! as well as the line number and then the string that was passed to it,
//! when the DEBUG macro is defined and does not print anything if the DEBUG
//! macro has not been defined
#define trace(f_, args...)

//! \def A debugging macro, which prints the function name which it was called from
//! as well as the line number and then the string that was passed to it,
//! when the DEBUG macro is defined and does not print the function name and line
//! number, but instead only prints the string that was passed to it, if the DEBUG
//! macro has not been defined
#define _printf(f_, args...)    printf(f_"\r\n", ##args)
#endif


//--------------------------------------------------------------
// Types

//! A structure used to encapsulate arguments sent to a new client thread handler
typedef struct _thread_args
{
    //! The index of the current thread
    uint32_t thread_count;

    //! The thead ID of the current thread
    pthread_t *thread_id;
} thread_args;

//! Command line options that can be used when running the application
static struct option long_options[] = {
   {"debug", optional_argument, 0, 0},
   {"help", optional_argument, 0, 0},
   {0, 0, 0, 0}
};


//--------------------------------------------------------------
// Function prototypes

//! \brief Thread handler used for each client thread created
//! \param threadArgs the encapsulated thread arguments containing the thread index and ID
//! \return
void *CLIENT_ThreadHandler(void *threadArgs);

//! \brief Attempt secure connection to the server specified by the url parameter
//! \param ssl The SSL instance created by the client
//! \param ctx The SSL context created by the client
//! \param url The server location in the format [host]:[port]
//! \return The BIO instance created if connection is successful
BIO *CLIENT_AttemptConnect(SSL *ssl, SSL_CTX *ctx, char *url);

//! \brief Attempt to create an SSL context
//! \return The SSL context if instantiation was successful
SSL_CTX *CLIENT_InitCTX(void);

//! \brief Attempts to write to the server
//! \param bio The BIO instance created when establishing a connection to the server
//! \param buff Buffer to be written to the server
//! \return TRUE for a successful write / FALSE for an unsuccessful write
uint8_t CLIENT_Write(BIO *bio, char *buff);

//! \brief Attempts to read from the server
//! \param bio The BIO instance created when establishing a connection to the server
//! \param threadArgs Encapsulated thread arguments containing the thread index and ID
//! \return TRUE for a successful read / FALSE for unsuccessful read
uint8_t CLIENT_Read(BIO *bio, thread_args *threadArgs);

//! \brief prints the usage, containing required and optional command line arguments
//! \param fileName argv[0] should be passed in this parameter which contains the name of the executable file
//! \return
static inline void CLIENT_PrintUsage(char *fileName);

//--------------------------------------------------------------
// User variables

//! BIO instance used for printing errors
BIO *outbio = NULL;

//! The url of the server in the format [host]:[port]
char *url = NULL;

//! The path to the file to be downloaded, must contain file extension
char *path = NULL;

//! The file name of the file to download which is obtained from the given path
char *fileExt;

//! Number of client instances which is defined by -n command-line argument, defaults to 1
uint32_t clientInstances = 1;

#endif
