CC = gcc
CFLAGS = -lssl -lcrypto -lpthread

server:
	$(CC) -c -Wall -g $(CFLAGS) server.c -Wextra
	$(CC) -c -Wall -Wextra -g $(CFLAGS) serverMain.c
	$(CC) -Wall -g -o serverMain serverMain.o server.o -lssl -lcrypto -lpthread

run-server: clean server
	$(CC) -c -Wall -Wextra -g $(CFLAGS) serverMain.c
	$(CC) -Wall -g -o serverMain serverMain.o server.o -lssl -lcrypto -lpthread
	./serverMain

clean:
	rm -f *.o *.exe *.out serverMain
	
	
	
	
