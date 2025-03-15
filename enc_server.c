#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);
  // Allow a client at any address to connect to this server
  address->sin_addr.s_addr = INADDR_ANY;
}

int charToNum(char c) {
  if(c == ' '){
    return 26;
  }
  return c - 'A';
}

char numToChar(int num){
  if (num == 26){
    return ' ';
  }
  return 'A' + num;
}

int recvAll(int s, char *buf, int *len){
  int total = 0;        
  int bytesleft = *len; 
  int n;

  while(total < *len) {
      n = recv(s, buf + total, bytesleft, 0);
      if (n == -1) { break; }
      if (n == 0) { break; } 
      total += n;
      bytesleft -= n;
  }

  *len = total; 

  return n == -1 ? -1 : 0; 
}

int sendAll(int s, char *buf, int *len)
{
    int total = 0;        
    int bytesleft = *len; 
    int n;

    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; 

    return n == -1 ? -1 : 0; 
}

int recvInt(int socket) {
  int value;
  int n = recv(socket, &value, sizeof(value), 0);
  if (n <= 0){
    error("ERROR receiving integer");
  } 
  return ntohl(value);
}

void encrypt(const char *plaintext, const char *key, char *ciphertext) {
  int textLen = strlen(plaintext);

  for (int i = 0; i < textLen; i++) {
      int plainNum = charToNum(plaintext[i]);
      int keyNum = charToNum(key[i]);
      int cipherNum = (plainNum + keyNum) % 27;
      ciphertext[i] = numToChar(cipherNum);
  }
  ciphertext[textLen] = '\0';
}

int main(int argc, char *argv[]){
  int connectionSocket, charsRead, textLen, keyLen;
  char buffer[256];
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);

  // Check usage & args
  if (argc < 2) { 
    fprintf(stderr,"USAGE: %s port\n", argv[0]); 
    exit(1);
  } 
  
  // Create the socket that will listen for connections
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) {
    error("ERROR opening socket");
  }

  // Set up the address struct for the server socket
  setupAddressStruct(&serverAddress, atoi(argv[1]));

  // Associate the socket to the port
  if (bind(listenSocket, 
          (struct sockaddr *)&serverAddress, 
          sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  // Start listening for connetions. Allow up to 5 connections to queue up
  listen(listenSocket, 5); 
  
  // Accept a connection, blocking if one is not available until one connects
  while(1){
    // Accept the connection request which creates a connection socket
    connectionSocket = accept(listenSocket, 
                (struct sockaddr *)&clientAddress, 
                &sizeOfClientInfo); 
    if (connectionSocket < 0){
      error("ERROR on accept");
    }

    // Receives Plaintext
    textLen = recvInt(connectionSocket);
    char *plaintext = malloc(textLen + 1);
    memset(plaintext, '\0', textLen + 1);

    recvAll(connectionSocket, plaintext, &textLen);

    // Receives Key
    keyLen = recvInt(connectionSocket);
    char *key = malloc(keyLen + 1);
    memset(key, '\0', keyLen + 1);
    recvAll(connectionSocket, key, &keyLen);

    // Create Ciphertext
    char *ciphertext = malloc(textLen + 1);
    encrypt(plaintext, key, ciphertext);

    // Send Ciphertext to client
    sendAll(connectionSocket, ciphertext, &textLen);

    // Free up memory
    free(plaintext);
    free(key);
    free(ciphertext);

    // Close the connection socket for this client
    close(connectionSocket); 
  }
  // Close the listening socket
  close(listenSocket); 
  return 0;
}