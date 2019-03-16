#ifndef SERVER_H
#define SERVER_H

/**
 * @file server.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Header This header provides the function protypes and constants used in the implementation of the BIO SSL threaded server. 
 * See files serverMain.c and server.c
 * 
 * @copyright Copyright &copy; 2019 - EHN 410 Group 7
 *
 */

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "malloc.h"
#include "unistd.h"
#include "getopt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h> 
#include <ctype.h>


#define STRING_SIZE 80
#define MIMETYPE "mime-types.tsv"

//! used to output the current port on which the server is listening.
extern char connectedPort[STRING_SIZE];

//! used to output the current hostname on which the server is listening.
extern char connectedHost[STRING_SIZE];

/**
 * @brief Function name: findPort
 * 	Used as a helper function to find a open port for the server to bind to. 
 * 	This function uses the port 4000 as a base port and adds the contents of @param counter to 4000. 
 *  Returns the string representation of the proposed port. 
 * 	Note: Does not check whether the "counter" variable is beyond a certain threshold - implementation specific. 
 * 	Does error checking to determine if the contents of @param counter is an integer. If it is not "-1" is returned to signify a problem. 
 * 
 * @param counter - Type: Integer. Contents of which are added to 4000 to specify a proposed port. 
 * @return char* - The string representation of the proposed port. 
 */
char* findPort(int);

/**
 * @brief TFunction name: getMimeType
 * This function is used to determine the mime-type of the file passed in as a paramter. 
 * It extracts the file extension of the filename passed in as @param name and searches the mime-types.tsv file 
 * for the appropriate mime-type. 
 * 
 * If the appropriate mime-type is found, it is returned as a char*, if not, the application/octet-stream mime-type is returned
 * to indicate to the client that the mime-type for the file is unknown. 
 * 
 * If a user wishes to add a mime-type + file extension combination to improve compatiblity, they may do so by editing the mime-types.tsv file 
 * found in the root directory of the server. Ensure that the format is adhered to and the number found on the first line of the file is incremented
 * to ensure that the newly added mime-type is considered. 
 * 
 * @param name - char* pointing to a C-Style string containing the path to file to be sent to client.
 * @return char* - the mime-type to use for the file requested.
 */
char * getMimeType(char *name);

/**
 * @brief Function name: constructHeader
 * This function constrcuts the response header sent to a client from the ssl server. 
 * Based off of the @param statusCode it constructs the appropiate response, the length of the response 
 * as well as the mimeType of the response file sent back to the client. 
 * Constructs the header according to the HTTP version 1.1 standard. 
 * 
 * returns the response header to be sent to the client. 
 * 
 * @param statusCode - char* to a C-String object containing the response status code to be sent to the client. 
 * @param length - unsigned long containing the length in bytes of the amount of data to be sent to client
 * @param mimeType - char* to a C-String object contsaing the apprtiate mime-type of the data to be sent as a response to the client request. 
 * @return char* - the constructed response header. 
 */
char *constructHeader(char *, unsigned long, char*);

/**
 * @brief Function name: parseRequest
 * This function processing the request received from the client. 
 * Since the ssl server only supports "GET" http requests, it scans the 
 * request received given in @param temp, for the directory of the file requested. 
 * 
 * The requested file is then returned. If a requested file could not be found in the request header,
 * due to HTTP protcol version mismatches or any other unknown reason, NULL is returned.  
 * 
 * @param temp - char* poinuting to a C-String containing the request received from the client.  
 * @return char* - the requested file from the request header. NULL if a file path could not be found in the 
 * request header. 
 */
char* parseRequest(char*);

/**
 * @brief Function name: sendResponse
 * This function is used to send the requested file given by @param resource to the client connected on
 * @param socket.
 * 
 * If the resoure is NULL signalling that the request header was malformed, the page not found error html page is 
 * sent as a response to the client. 
 * 
 * If the ressource requested points to a directory or the requested file is not found, the page not found error page is 
 * sent as a response to the client. 
 * 
 * If client sends a GET / request to the server, the default index.html homepage is sent as a response. 
 * 
 * If the requested resource could be found the server root directrory or sub directroy, it is sent to the client. 
 * The main purpose of this function is to determine which response is sent to the clinet. 
 * It calls the sendFile function to send/write the appropriate file to the BIO socket. 
 * 
 * @param socket - BIO* pointing to the BIO object on which the client is paired/connected. 
 * @param resource - char* pointing to a c-string object conting the path to the requested resoure received from the clinet. NULL if the client 
 * sent a malformed request. 
 */
void sendResponse(BIO*, char *);

/**
 * @brief Function name: printHelp
 * Prints out the help menu or usage menu for the ssl server. 
 * Called when the user inputs invalid parameters or the -h (help) flag is set by the user. 
 */
void printHelp();

/**
 * @brief Function name: theServer.
 * Intended use is as a multithreaded function. Used to thread the server listening on a port. 
 * Should the server not be able to bind the specifed port, it will spawn a new thread to the smartServer() function in order to 
 * find a reasonable open port and this function will end. 
 * Should the server have the ability to bind to the specified port, it will bind to it and run and inifinite loop listening for socket connections
 * on that port. Once a client attempts to make a connection, the function will spawn a new thread for that client - running the aClient() function 
 * allowing for multiple clients to be handled simultaneously, each within its own thread. 
 * 
 * @param bioPtr - BIO* pointing to a BIO object with the ssl and tcp wrapping already implemented to enable a listening socket
 * @return void* - Returns NULL, since the intended use is as a POSIX threaded function
 */
void* theServer(void *);

/**
 * @brief Function name: sendFile
 * This function sends or writes the appripate file to the BIO object/socket connected to the client. 
 * The function attempts to open the file with the path given by @param fileName and writes the file in "chunks" of
 * 2048 bytes. The contents of the opened file is read into a buffer and the contents of the buffer are written to the socket 
 * until the end of the file has been reached. The file is read at a rate of 2048 bytes per write. Once the entire contents of the file
 * has been written the BIO object is flushed to ensure all data is sent and the function returns. 
 * 
 * This function first constructs the appropriate response header, sends the response header, thereafter sending or writing the 
 * requested file. 
 * 
 * If the file could not be opened, due to it not existing in the root directory or sub-directory of the ssl server program, the 
 * function returns without writing anything to the client. 
 * 
 * @param socket - BIO* to a BIO object connecting the client to the ssl server. 
 * @param fileName - char* pointing to a C-String containing the requested file
 * @param statusCode - char* pointing to a C-String containing the appropiate status code to send to the client within the response header. 
 */
void sendFile(BIO* socket, char*,char*);

/**
 * @brief Function name: aClient
 * This a function intended to be used in a multithreaded manner. 
 * This function handles a connection between the secure ssl server and the client. 
 * 
 * This function is spawned when a client connects to the server. 
 * The function first performs the ssl handhake to ensure that the connection between the server and the client is secure. 
 * If the handshake fails for whatever reason, the connection is terminated and the function returns. 
 * Thereafter the client request is read into a buffer.
 * If the client request could not be read or the connection has been disconnected, the function terminates the connection (if connected) and returns. 
 * Once the client request is successfully read, the request is processed and the response is sent or written to the requested client. 
 * Thereafter the connection to the client is terminated and the function returns. 
 * 
 * This function is called in a new thread each time a new client request is received, since each new request is a new connection. 
 * The server does not store any information about a client after the connection is terminated and each connection is treated as the first initial connection.
 * 
 * @param socket - BIO* pointing to a bio object that is connected to the client. The socket on which the current connection is done. 
 * @return void* - Returns NULL, since the intended use is as a POSIX compliant threaded function
 */
void* aClient(void *);

/**
 * @brief Function name: smartServer. 
 * This function is a multithreaded function called when the requested port or default port for the SSL server could not be binded to,
 * due to the port being blocked, restricted or already reserved. 
 * 
 * This function attempts to bind to an alternate port within the range 4000-4049. If no port within this range could be binded to 
 * the function ends the program, alerts; the user that no port could be found and requests the user re-run the ssl server with an alternate port speciifed. 
 * 
 * If a port could be binded to it functions in the same manner as the function theServer. See function: theServer. 
 * 
 * @return void* - NULL to signify the end of the thread. 
 */
void* smartServer();

#endif 

