/**
 * @file server.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief  Server function implementation file.
 * This file contains the function implementation source code used to run the ssl server. 
 * @version 0.1
 * @date 2019-02-13
 * 
 * @copyright Copyright &copy; 2019 - EHN 410 Group 7
 * 
 */
#include "server.h"

//! used to output the current port on which the server is listening.
char connectedPort[STRING_SIZE] = "empty";

//! used to output the current hostname on which the server is listening.
char connectedHost[STRING_SIZE] = "empty";

/**
 * @brief Function name: printHelp
 * Prints out the help menu or usage menu for the ssl server. 
 * Called when the user inputs invalid parameters or the -h (help) flag is set by the user. 
 */
void printHelp()
{	
	printf("A simple secure HTTPS webserver \n");
	printf("\nUsage ./serverMain.out <optional paramters> <optional arguments> \nIf no arguments are specified the default parameter values are used.\n\n");
	printf("-h \t \t \t Prints out the help menu \n");
	printf("-p \t \t \t To specify the port to use.            \t Default: 4001\n");
	printf("-k \t \t \t To specify the key file to use         \t Default: webServ.key\n");
	printf("-c \t \t \t To specify the certificate file to use \t Default: webServCert.crt\n\n");
	
}

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
char* findPort(int counter)
{
    	char *myString = malloc(20*sizeof(char));
    	sprintf(myString, "%d", counter + 4000);
    	return myString;
 }

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
void *theServer(void *bioPtr)
{
	BIO_set_nbio_accept((BIO*)bioPtr,0);
    fflush(stdout);
	while(1){
		fflush(stdout);
		if (BIO_do_accept((BIO*)bioPtr) <= 0) {
			printf("ERROR: could not accept socket\n");
			fflush(stdout);
			BIO_free((BIO*)bioPtr);
			pthread_t threadID;
        	pthread_create(&threadID, NULL,smartServer,NULL);
            return NULL;			
		}
		// Set the hostname and port
		if(BIO_get_accept_name((BIO*)bioPtr) != NULL){
			strcpy(connectedHost, BIO_get_accept_name((BIO*)bioPtr));
		}

		if(BIO_get_accept_port((BIO*)bioPtr) != NULL){
			strcpy(connectedPort, BIO_get_accept_port((BIO*)bioPtr));
		}
		
		BIO* tempBio = BIO_pop((BIO*)bioPtr);
		if(tempBio == NULL){
			continue;
		}
        pthread_t threadID;
        pthread_create(&threadID, NULL,aClient,tempBio);
		printf("Client thread created\n");	
	}	
	return NULL;
}

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
void *aClient(void* socket)
{
	printf("\nClient request received\n");

	//Socket has become invalid for an undefined reason
	if((BIO*)socket == NULL)
	{
		return NULL;
	}

	// do ssl handshake with the client 
	 if (BIO_do_handshake((BIO*)socket) <= 0) {
		fprintf(stderr, "Error in SSL handshake\n");		
		BIO_free_all((BIO*)socket);
		return NULL;
 	}
	usleep(1000); //ensure that the ssl handshake occurs and processes correctly. 
	 
	printf("Client ssl handshake success\n");

	int readBuffer_size = 1024;	
	char * readBuffer = malloc(sizeof(char)*1024);

	if((BIO*)socket == NULL)
	{
		return NULL;
	}
	
	// read information received from the client 
	int read_result = BIO_read((BIO*)socket,readBuffer,readBuffer_size);

	printf("Read result from client is: %d\n", read_result);
	
	//Could not read from client 
	if (read_result  <= 0) {
		ERR_print_errors_fp(stdout);
		BIO_free((BIO*)socket);
		free(readBuffer);
		return NULL;
		
	} else {
		printf("Parsing request from client\n");		
		char * reqResource = parseRequest(readBuffer); // the requested resource
		sendResponse((BIO*)socket, reqResource); // send the response to the client 
	}
	// close the connection
	BIO_free((BIO*)socket);
	free(readBuffer);
	return NULL;
}

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
char* parseRequest(char* temp)
{
	printf("Original request header is :_%s_\n", temp);
	char* token_string ;
	token_string = strdup(temp);
	const char s[3] = " \n";
	char *token ;	
	token = strtok(token_string, s); //tokenize the request header 
	printf("First token is :_%s_\n", token);
	token = strtok(NULL, s); //get second one
	printf("Second token is:_%s_\n", token);
	
	if( token != NULL )
	{	
		char *returnTemp = strdup(&token[0]);
		free(token_string);
		return returnTemp;
	}
	free(token_string);
	return NULL;
}

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
void sendResponse(BIO* socket, char *resource)
{
	if(resource == NULL)
	{
		printf("ERROR: unable parse request - sending error page.\n");
		resource = "/error.html";
		sendFile(socket,resource+1,"404");
  		return;
	} 

	if(strcmp(resource+(strlen(resource)-1),"/") == 0 && strlen(resource)>1)
	{		
		printf("ERROR: unable parse request - sending error page.\n");
		resource = "/error.html";
		sendFile(socket,resource+1,"404");
  		return;
	}
	if(strstr("/",resource) != NULL){
		resource = "/index.html";
	}
	FILE* fp = NULL;
    
	if(strstr("/",resource) != NULL){
		resource = "/index.html";
	}

	printf("RESOURCE IS _%s_\n", resource);	   
    
	fp = fopen(resource+1,"r");
    
	if(fp == NULL) {
   		printf("ERROR: unable to open file %s.\n",resource);
		resource = "/error.html";
		sendFile(socket,resource+1,"404");
  		return;
   } else{
		fclose(fp);
		sendFile(socket,resource+1,"200"); //rename to send file
   }
}

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
char *constructHeader(char * statusCode, unsigned long length, char* mimeType)
{
	printf("The length is :%ld\n", length);
	FILE *stream;
	char *buf;
	size_t len;
	stream = open_memstream(&buf, &len);
	// write what you want with fprintf() into the stream
	
	fprintf(stream, "HTTP/1.1 ");
	fprintf(stream, "%s", statusCode);
	printf("STATUS CODE:____%s____\n", statusCode);
	if(strcmp(statusCode,"200") == 0){
		fprintf(stream, " OK");
	} else{ 
		fprintf(stream, " Not Found");
	}
	fprintf(stream, "\r\nContent-Type: ");
	fprintf(stream,"%s",mimeType);
	fprintf(stream,"\r\n\r\n");
	fflush (stream);
	// close the stream, the buffer is allocated and the size is set !
	fclose(stream);
	printf("header is \n%s\n", buf);
	return buf;
}

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
void sendFile(BIO* socket, char* fileName, char* statusCode) 
{
   FILE* fp = NULL;
  
   unsigned long fileLen = 0;	   
   fp = fopen(fileName,"r");

   if( fp == NULL ) {
   		printf("ERROR: unable to open file.%s\n",fileName);
  		return;
   }
   fseek(fp,0,SEEK_END);
   fileLen = ftell(fp);
   fseek(fp,0,SEEK_SET);
   printf("\n\n ________________\n MIMTYPE: %s\n", getMimeType(fileName));
   char * header = constructHeader(statusCode,fileLen, getMimeType(fileName));
   // Write the header
   printf("The header is that is sent\n%s\n",header);
   BIO_write(socket,header,strlen(header));
   int bytesread;
   unsigned char buffer[2048];

   // Continuously write the file to bio until the whole file is written
   while(1){
	    bytesread = fread(buffer,sizeof(unsigned char),2048,fp);
		if(bytesread == 0){
			break;
		}
		
		if(BIO_write(socket,buffer,bytesread) <= 0){
			printf("write failed\n");
			break;
		}		
   }
   BIO_flush(socket); //flush data to the client
   fclose(fp);
}

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
void* smartServer()
{
	printf("Error, the port specified was closed, attempting to self-correct\n");	
	int counter = 1;
	BIO *bio;
	fflush(stdout);		
	counter = 1;
	char * tempPort = findPort(counter);
	printf("Attempting to connect to port %s", tempPort);
	bio = BIO_new_accept(tempPort);
	fflush(stdout);
	if (BIO_do_accept(bio) <= 0) {
		printf("Error: Could not setup the socket\n");
		BIO_free(bio);
		printf("The server will now exit, please run again with another port number specified.\n");
		exit(0);
	}

	BIO_set_nbio_accept(bio,0);
	while(1) {
		// Look for a port to bind to. end at 4049
		while(BIO_do_accept(bio) <= 0) {
			if(counter > 50){
				printf("Error: Could not bind to given port and could not find a port within the range 4000-4050 to bind to.\n");
				printf("The server will shutdown, please re-run and specify another port.");
				exit(0);
			}
			fflush(stdout);
			printf("ERROR: could not accept socket\n");
			BIO_free(bio);
			counter += 1;
			tempPort = findPort(counter);
			printf("Attempting to connect to port %s\n", tempPort);
			bio = NULL ;
			fflush(stdout);
			bio = BIO_new_accept(tempPort);
			if (BIO_do_accept(bio) <= 0) {
				printf("Error: Could not setup the socket\n");
				BIO_free(bio);
				printf("The server will now exit, please run again with another port number specified.\n");
				exit(0);
			}
			BIO_set_nbio_accept(bio,0);			
		}
		// Set the hostname and port
		if(BIO_get_accept_name(bio) != NULL){
			strcpy(connectedHost, BIO_get_accept_name(bio));
		}

		if(BIO_get_accept_port(bio) != NULL){
			strcpy(connectedPort, BIO_get_accept_port(bio));
		}
		fflush(stdout);
		BIO* tempBio = BIO_pop(bio);
		pthread_t threadID;
		pthread_create(&threadID, NULL,aClient,tempBio); // spawn a client handler thread (aClient)	
	} //End infinite listen loop
	return NULL;	
}


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
char * getMimeType(char *name) 
{
	char *ext = strrchr(name, '.');
    char delimiters[] = " ";
	char *mimeType = NULL;
	int found = 0;
	mimeType = malloc(128 * sizeof(char)); //return variable
	char line[128];
	char *token;
	int line_counter = 1;
	//ext++; // skip the '.';
	FILE *mimeFile = fopen(MIMETYPE, "r"); //open the mime-type.tsv

	if(mimeFile != NULL){
		while(fgets(line, sizeof line, mimeFile) != NULL) {
			if(line_counter > 1) {
				if((token = strtok(line,delimiters)) != NULL) {
					if(strcmp(token,ext) == 0) {
						// found the appropriate mime-type
						token = strtok(NULL, delimiters);
						strcpy(mimeType, token);
						found = 1;
						break;
					}
				}
			}
			line_counter++;
		}
		fclose(mimeFile);
	}else {
		printf("WARNING: Mime-types file not found, please add it to server root.\nFile must be named: \"mime-types\"\nType set to: application/octet-stream");
		mimeType = "application/octet-stream";
	}

	if(found == 0){
		mimeType = "application/octet-stream"; //signify unknown mime-type
	}	
	return mimeType;
}
