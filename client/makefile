URL = sample-videos.com:443/img/Sample-jpg-image-50kb.jpg
NUM_THREADS = 5

TARGET = client
DEBUG = debug
DOWNLOAD_FOLDER = downloads

CC = gcc
CFLAGS = -Werror -Wall -lssl -lcrypto -lpthread
DEBUG_FLAG = DEBUG
	
$(TARGET): $(TARGET).c $(TARGET).h
	$(CC) -D HTTP_DOWNLOAD_PATH=\"$(DOWNLOAD_FOLDER)\" $(TARGET).c $(CFLAGS) -o $(TARGET)
	
$(TARGET)-$(DEBUG): $(TARGET).c $(TARGET).h
	$(CC) -D $(DEBUG_FLAG) -D HTTP_DOWNLOAD_PATH=\"$(DOWNLOAD_FOLDER)\" $(TARGET).c $(CFLAGS) -o $(TARGET)
	
all: clean $(TARGET)
	
$(DEBUG): $(TARGET)-$(DEBUG)
	
run: $(TARGET)
	./$(TARGET) -u $(URL) -n $(NUM_THREADS)

clean:
	rm -f *.o *.out $(TARGET)
	rm -rf $(DOWNLOAD_FOLDER)/