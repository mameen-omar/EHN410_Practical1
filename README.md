************************************				
# EHN 410 - Group 7
************************************				
# Practical 1:
Implementation of a SSL client and server in C using the BIO library and Public-key Cryptography. 
************************************
## Group members:
* Mohamed Ameen Omar 	(u16055323)
* Llewellyn Moyse 	(u15100708)
* Douglas Healy 	(u16018100)

**************************
### To run the ssl-server:
**************************
1. Open the terminal.
2. Navigate to the server root directory.
3. Ensure that the certificate files are in the root directory of the server (or sub-directory of the server).
4. Run the command make server.
5. The server program will be compiled and the executable will be called "serverMain".
6. Run the server using the default parameters using the command ./serverMain 
7. Enter the PEM password (the default certificate and key password is: 'password')
8. The server will now be active and running.

* To automatically compile and run the server with default parameters, run the command make run-server
  * to view the server help menu run: ./serverMain -h
  * to specify a port use the -p flag followed by the port on which you would like the server to listen. (example ./serverMain -p 3559). 
* If no hostname is specified with the port (-p hostname:port), the server by default listens on all available interfaces for an incoming connection.
* the user is able to change the certificate and key files for the server as well. Please view the server help menu for further details. 
* The mime-types.tsv file in the server root directory is used to determine the mime-type to specify in the server response header. If this file
is not in the root directory or the mime-type for a file is not in this file, the secure server will default to the "application/octet-stream" mime-type being 
specified and as such, will not notify the client what type of file is being sent. 
* The secure server adheres to the HTTP 1.1 standard and only caters for GET requests from a client. Additional functionality was not required. 

************************************
### To run a client in the terminal:
************************************
1. Open the terminal.
2. Navigate to the client root directory.
3. Run the command make all.
4. The client program will be compiled and the resulting executable will be called "client".
5. Run the client providing the -u command-line argument which should specify a path to a file on the server (eg. [host]:[port]/[filename].[extension]).
6. An optional -n command-line argument can be defined which will specify how many instances of the client should be spawned.
7. The client will now run and the file that was specified will attempt to download.

* A path to an existing file on an external web-server is defined within the makefile and can be run using the 'make run' command.
* Issuing the command "./client --help" or "./client -h" will print a help menu and provide insight on the accepted command line arguments.


#### An absolute path to a file must be specified including the file name and extension.

********************************************
### To access server files in a web browser:
********************************************
1. Install all the server certificates in the web browser to be used (e.g Firefox).
2. To do this, Go to the Certificate Manager in Firefox
  * Click on Tools->Options->Advanced, 
  * Click on the Encryption Tab and click on View Certificates,
  * Click on the Authorities tab and click Import, then
  * Select your created certificate and provide the necessary permissions.
3. Ensure that the server is running. 
4. Navigate to the SSL server page in the browser: https://hostname:port (example: https://localhost:40001/)
5. The homepage will load.
6. Click on the links provided.
7. Navigate to unlisted files to download files that are not added by default (example: https://localhost:40001/resources/sample.mp3)

* If the certificate files are not installed before accessing the server webpage, the page will appear as "untrusted", add as an exception, 
and continue to the server homepage.
************************************				
# References:
* OpenSSL documentation: http://www.openssl.org/docs/ssl/
* Generating certificates: http://gagravarr.org/writing/openssl-certs/index.shtml

