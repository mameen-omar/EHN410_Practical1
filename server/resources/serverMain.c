// EHN 410 - Mohamed Ameen Omar - u16055323 - 2019

/**
 * @file serverMain.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief  Main file to run the ssl server. 
 * 
 * This program will run a ssl server that is confiurable by PORT, IP and certificates used. 
 * All connections are created and managed using the using the OpenSSL BIO library. 
 * The program can take in commandline arguments to specify the PORT, IP, keys and certificates used for the server. 
 * 
 * If no commandline arguments are specifed, the server defaults to listen on all connected interfaces and port 4001, using
 * the certificates and keys given in the root directory of the server (filenames: cert.key, cert.crt). 
 * 
 * The server first attempts to open the certficate and key files specifed and queries for the PEM passkey on success, a new SSL BIO TCP 
 * listen socket is created. The listen socket runs in it's own thread, spawning a new thread for each client conenction. 
 * The program then continues to wait for user input, should "q" be entered, the program will exit and all connected clients will disconnect. 
 * Should "i" be entered, information regarding the current listening port and hostname for the server is shown. 
 * 
 * The server continuously prints out debugs to enable the user to view what th server is doing and who is connecting. All resources requested are 
 * are printed out to the terminal window. 
 * 
 * This server is developed as part of the required practicals for EHN-410 at the University of Pretoria. 
 * 
 * This server is intended to be compatible with the firefox browser and the accompanying ssl-client. Any other clinet attempting to connect is not 
 * guaranteed to be compatible. 
 * 
 * Please note that the mime-types.tsv file is required for the server to run correctly, should the file not exist, it must be created to ensure
 * compatibility with clients and various content types. 
 * 
 * @version 0.1
 * @date 2019-02-13
 * 
 * @copyright Copyright &copy; 2019 - EHN 410 Group 7
 * 
 */

#include "server.h"

extern char connectedPort[STRING_SIZE]; //used to output the current port on which the server is listening. 
extern char connectedHost[STRING_SIZE]; //used to output the current hostname on which the server is listening. 


int main(int argc, char * argv[])
{
    char* PORT = "4001";
    char* certificate = "webServCert.crt";
    char* key = "webServ.key";
    int ch; // used for commandline flags and parameters (getopt) 

    while((ch = getopt(argc, argv, "p:hc:k:")) != EOF)
    {
        switch (ch)
        {   
            //help menu specified
            case 'h':
                printHelp();
                exit(EXIT_SUCCESS);
            //port specified
            case 'p':
                PORT = optarg;
                printf("The port specified is %s\n", PORT);
                break;

            case 'c':
                certificate = optarg;
                printf("The certificate specified is %s\n", certificate);
                break;
            
            case 'k':
                key = optarg;
                printf("The key specified is %s\n", key);
                break;

            case '?':
                printHelp();
                break;
            
            default:
                printHelp();
        }
    }
    
    /* Initializing OpenSSL */
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    
    SSL_load_error_strings();
	SSL_library_init();    

    // Setup ssl key + cert

    BIO* ssl_server_bio; 
	SSL_CTX* ctx;
	SSL* ssl;
	
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) 
	{
		printf("ERROR: failed to create the SSL context\n");
		return 0;
	}

    printf("The key is %s\n", key);
    printf("The port is %s\n", PORT);
    printf("The cert is %s\n", certificate);

    if ( !SSL_CTX_use_certificate_file(ctx,certificate, SSL_FILETYPE_PEM) ) 
	{
	    printf("ERROR: failed to load certificate file\n");
        ERR_print_errors_fp(stdout);
	    return 0;
    }

    if ( !SSL_CTX_use_PrivateKey_file(ctx,key, SSL_FILETYPE_PEM) ) 
    {
	    printf("ERROR: failed to load key file\n");
        ERR_print_errors_fp(stdout);
	    return 0;
    }

    ssl_server_bio = BIO_new_ssl(ctx, 0);
	if (ssl_server_bio == NULL) 
	{
		printf("ERROR: failed retrieving the BIO object\n");
        ERR_print_errors_fp(stdout);
		return 0;
	}

	BIO_get_ssl(ssl_server_bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);		
	
    printf("Attempting to create socket on port %s\n", PORT);
    BIO *bio;
    bio = BIO_new_accept(PORT);
    BIO_set_accept_bios(bio, ssl_server_bio);	    
	BIO_set_nbio_accept(bio,0);    

    // if the socket fails to bind to the TCP wrapper. 
    if (BIO_do_accept(bio) <= 0) {
        printf("Error: Could not setup the socket\n");
        BIO_free(bio);
        printf("The server will now exit, please run again with another port number specified.\n");
        exit(0);
    }

    printf("Server online\n");

    // create the server thread
    pthread_t threadID;
 	pthread_create(&threadID,NULL,theServer,bio);
    fflush(stdout);
    while(1) {
        fflush(stdout);
        printf("ENTER \"q\" to close server\n");
        printf("ENTER \"i\" to display status\n");
        char input;
        scanf(" %c",&input);
        if( input == 'q'){
            break;
        } else if(input == 'i') {
            printf("\nYou have requested the server status:\n");
            if(strcmp(connectedHost,"empty") == 0) {
                printf("The server has not received any connections.\n");
            } else {
                printf("The connected host is: %s\n", connectedHost);
                printf("The connected port is: %s\n\n", connectedPort);
            }
         } else { 
            printf("INFO: unknown command. Please Enter a valid command \n");
        }         	  
    }	
	printf("\nServer closed\n");
	pthread_cancel(threadID);
	BIO_free(bio);
    BIO_free_all(bio);
	return 0;
}
    
