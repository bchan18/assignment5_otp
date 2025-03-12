#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()


#define VALID_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
#define MAX_BUFFER_SIZE 1000


/**
* Client code
* 1. Create a socket and connect to the server specified in the command arugments.
* 2. Prompt the user for input and send that input as a message to the server.
* 3. Print the message received from the server and exit the program.
*/

// Error function used for reporting issues
void error(const char *msg) { 
  perror(msg); 
  exit(0); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber, 
                        char* hostname){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);

  // Get the DNS entry for this host name
  struct hostent* hostInfo = gethostbyname(hostname); 
  if (hostInfo == NULL) { 
    fprintf(stderr, "enc_client: ERROR, no such host\n"); 
    exit(0); 
  }
  // Copy the first IP address from the DNS entry to sin_addr.s_addr
  memcpy((char*) &address->sin_addr.s_addr, 
        hostInfo->h_addr_list[0],
        hostInfo->h_length);
}


// Send all the data
void sendAll(int socketFD, char *buffer, int length){
  int charsWritten;
  int totalSent = 0;

  while (totalSent < length){
      charsWritten = send(socketFD, buffer + totalSent, length - totalSent, 0);
      if (charsWritten < 0) error("enc_client error: writing to socket");
      totalSent += charsWritten;
  }
}


// Receive all the data
void recvAll(int socketFD, char *buffer, int length){
  int charsRead;
  int totalReceived = 0;

  while (totalReceived < length){
      charsRead = recv(socketFD, buffer + totalReceived, length - totalReceived, 0);
      if (charsRead < 0) error("enc_client error: reading from socket");
      totalReceived += charsRead;
  }
}


// Checks for bad characters
void validate(const char *buffer, const char *filename){
  if (strspn(buffer, VALID_CHARS) != strlen(buffer)) {
      fprintf(stderr, "enc_client error: input contains bad characters\n");
      exit(1);
  }
}


// Read the plaintext file
char *readFile(const char *filename, int *length){
  FILE *file = fopen(filename, "r");

  if (file == NULL) {
      fprintf(stderr, "enc_client error: opening file %s\n", filename);
      exit(1);
  }

  // Determines file size
  fseek(file, 0, SEEK_END);
  *length = ftell(file);
  rewind(file);

  char *buffer = malloc((*length) + 1);
  if (!buffer) {
      fprintf(stderr, "enc_client error: allocating memory for file %s\n", filename);
      exit(1);
  }

  fread(buffer, 1, *length, file);
  fclose(file);

  // Removes newline in the file
  buffer[*length - 1] = '\0';
  (*length)--;

  return buffer;
}


int main(int argc, char *argv[]) {
  int socketFD, plaintextLength, keyLength, sendSize;
  int sent = 0;
  struct sockaddr_in serverAddress;
  char buffer[256];
  // Check usage & args
  if (argc < 4) { 
    fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
    exit(1); 
  }

  // Read files
  char *plaintext = readFile(argv[1], &plaintextLength);
  char *key = readFile(argv[2], &keyLength);

  // Checks for bad characters
  validate(plaintext, argv[1]);
  validate(key, argv[2]);

  // Check if key is shoter than plaintext
  if (keyLength < plaintextLength){
    fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
    exit(1);
  }

  // Create a socket
  socketFD = socket(AF_INET, SOCK_STREAM, 0); 
  if (socketFD < 0){
    error("CLIENT: ERROR opening socket");
  }

   // Set up the server address struct
  setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");

  // Connect to server
  if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
    fprintf(stderr, "enc_client error: could not contact enc_server on port %s\n", argv[3]);
    exit(2);
  }

  // Sends the all the data to enc_server
  sendAll(socketFD, (char *)&plaintextLength, sizeof(int));

  while (sent < plaintextLength) {
    if (plaintextLength - sent < MAX_BUFFER_SIZE) {
        sendSize = plaintextLength - sent;
    } else {
        sendSize = MAX_BUFFER_SIZE;
    }
    sendAll(socketFD, plaintext + sent, sendSize);
    sendAll(socketFD, key + sent, sendSize); 
    sent += sendSize;  
  }

  // Free up allocated buffers
  free(plaintext);
  free(key);

  char *ciphertext = malloc(plaintextLength + 1);
    if (!ciphertext) {
        fprintf(stderr, "enc_client error: allocating memory for ciphertext\n");
        exit(1);
    }
  
  // Clear out the buffer again for reuse
  memset(ciphertext, '\0', plaintextLength + 1);

  // Receives all the data
  recvAll(socketFD, ciphertext, plaintextLength);

  // Free up allocated buffers
  free(ciphertext);

  // Close the socket
  close(socketFD); 
  return 0;
}