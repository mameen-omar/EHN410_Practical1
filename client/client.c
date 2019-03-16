//! \file client.c
//! \authors Douglas Healy (u16018100)
//! \authors Llewellyn Moyse (u15100708)
//! \authors Mohamed Ameen Omar (u16055323)
//! \date 2019/02/14
//! \brief Client program able to establish an SSL connection to a specified server
//! \version 1.0
//! \copyright Copyright &copy; 2019 - EHN410 Group 7


//--------------------------------------------------------------
// Includes
#include "client.h"


//--------------------------------------------------------------
// Function implementations
int main(int argc, char **argv)
{
    uint8_t i;

    int c = 0, option_index = 0; // option index for command-line args
    while ((c = getopt_long(argc, argv, "u:n:h::", long_options, &option_index)) != EOF) {
        switch (c) {
            case 0: // Currently not being used
                switch (option_index) {
                    case 0:
                        trace("Debugging mode enabled");
                        break;
                    case 1:
                        trace("Printing help menu (long option)");
                        CLIENT_PrintUsage(argv[0]);
                        exit(EXIT_FAILURE);
                        break;
                }
                break;

            case 'u':
                url = malloc(1024 * sizeof(char));
                path = malloc(1024 * sizeof(char));

                if (strstr(optarg, "/") == NULL) {
                    strcpy(path, "/");
                } else {
                    strcpy(path, strstr(optarg, "/"));
                }

                strcpy(url, strtok(optarg, "/"));
                trace("Host address: %s", url);
                trace("Path: %s", path);
                break;

            case 'n':
                clientInstances = atoi(optarg);
                trace("Client instances: %d", clientInstances);
                break;

            case 'h':
                trace("Printing help menu (short option)");
                CLIENT_PrintUsage(argv[0]);
                exit(EXIT_FAILURE);
                break;

            default:
                fprintf(stderr, "Incorrect option specified. Exiting...\n");
                exit(EXIT_FAILURE);
                break;
        }
    }

    // Check if all command-line arguments were provided
    if (url == NULL || path == NULL) {
        _printf("Missing required parameter [-u]");
        CLIENT_PrintUsage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Get file extension
    fileExt = strstr(path, ".");

    while (fileExt != NULL) {
        if (strstr(fileExt+1, ".") == NULL) {
            break;
        } else {
            fileExt = strstr(fileExt+1, ".");
        }
    }

    if (fileExt == NULL) {
        _printf("Can't find file extension in path, Exiting...");
        exit(EXIT_FAILURE);
    } else {
        trace("File extension: %s", fileExt);
        if (strstr(fileExt, "/") != NULL) {
            _printf("Can't find file extension in path, Exiting...");
            exit(EXIT_FAILURE);
        } else {
            trace("Found file extension: %s", fileExt);
        }
    }

    // Initialization
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    outbio = BIO_new_fp(stdout, BIO_NOCLOSE); // Set file output stream to standard output for debugging

    trace("URL: %s", url);

    pthread_t thread_id[clientInstances];
    for (i = 0; i < clientInstances; ++i) {
        thread_args threadArgs = { .thread_id = &thread_id[i], .thread_count = i };
        if (pthread_create(&thread_id[i], NULL, CLIENT_ThreadHandler, &threadArgs) != 0) {
            fprintf(stderr, "Error creating thread. Exiting...\n");
            exit(EXIT_FAILURE);
        } else {
            trace("Thread created with ID: %ld", thread_id[i]);
        }

        pthread_join(thread_id[i], NULL);
    }

    // Release all client threads
    for (i = 0; i < clientInstances; ++i) {
        pthread_cancel(thread_id[i]);
    }

    BIO_free_all(outbio);
    return EXIT_SUCCESS;
}

BIO *CLIENT_AttemptConnect(SSL *ssl, SSL_CTX *ctx, char *url)
{
    if (ctx != NULL) {
        _printf("Attempting to connect to %s", url);
    }
    BIO *_bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(_bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(_bio, url);

    if (BIO_do_connect(_bio) <= 0) {
        BIO_free_all(_bio);
        trace("Unsuccessful connection");
        fprintf(stderr, "Error connecting to server. Exiting...\n");
        exit(EXIT_FAILURE);
    } else {
        _printf("Secure connection to %s successful", url);
        _printf("SSL Cipher: %s\r\n", SSL_get_cipher(ssl));
    }

    return _bio;
}

void *CLIENT_ThreadHandler(void *args)
{
    thread_args *threadArgs = (thread_args*) args;
    BIO *bio = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ctx = CLIENT_InitCTX();

    _printf(COLOUR_RED"\r\nClient %d (Thread ID: %ld) attempting to connect..."COLOUR_RESET, \
            threadArgs->thread_count+1, (long int) threadArgs->thread_id);

    bio = CLIENT_AttemptConnect(ssl, ctx, url);

    char writeBuff[WRITE_BUFFER_SIZE];
    sprintf(writeBuff, "GET %s HTTP/1.1"HTTP_DELIM"Host: %s"HTTP_DELIM"Accept: "HTTP_DELIM"Connection: close"HTTP_DELIM""HTTP_DELIM, path, url);
    trace("Writing to server:\n%s", writeBuff);
    if (!CLIENT_Write(bio, writeBuff)) {
        fprintf(stderr, "Unable to write to server. Exiting...\n");
        exit(EXIT_FAILURE);
    }

    _printf("Attempting to download from %s%s", url, path);
    CLIENT_Read(bio, threadArgs);

    SSL_CTX_free(ctx);
    BIO_free_all(bio);
    return NULL;
}

SSL_CTX *CLIENT_InitCTX(void)
{
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

uint8_t CLIENT_Write(BIO *bio, char *buff)
{
    if(BIO_write(bio, buff, strlen(buff)) <= 0) {
        if(!BIO_should_retry(bio)) {
            fprintf(stderr, "Error writing to server. Exiting...\n");
            return FALSE;
        }
    }
    return TRUE;
}

uint8_t CLIENT_Read(BIO *bio, thread_args *threadArgs)
{
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    char *fileName = malloc(256*sizeof(char));
    sprintf(fileName, HTTP_DOWNLOAD_PATH"/CLIENT_%d[%d_%d_%d-%d_%d_%d]%s", \
            threadArgs->thread_count+1, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, \
            tm.tm_hour, tm.tm_min, tm.tm_sec, fileExt);

    trace("File name: %s", fileName);
    mkdir(HTTP_DOWNLOAD_PATH, 0700);

    FILE *fp;
    fp = fopen(fileName, "wb");
    int buffLen = 0, buffCount = 0, totalLen = 0;

    do {
        char buff[READ_BUFFER_SIZE] = {};
        buffLen = BIO_read(bio, buff, sizeof(buff));

        if (buffLen > 0) {
            if (buffCount == 0) {
                char *content = strstr(buff, HTTP_DELIM""HTTP_DELIM) + 4;
                fwrite(content, buffLen - (int)((long int)content - (long int) buff), sizeof(char), fp);
            } else {
                fwrite(buff, buffLen, sizeof(char), fp);
            }

            totalLen += buffLen;
            trace("%d bytes writting to %s", buffLen, fileName);
        }

        buffCount++;
    } while (buffLen > 0 || BIO_should_retry(bio));

    fclose(fp);
    _printf("%d bytes written to %s", totalLen, fileName);
    return TRUE;
}

static inline void CLIENT_PrintUsage(char *fileName)
{
    _printf("usage: %s\t[-u host:port/path]\n\t\t[-n client-instances] [-h help]", fileName);
    return;
}
