#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()

#define VALID_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

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
    fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
    exit(0); 
  }
  // Copy the first IP address from the DNS entry to sin_addr.s_addr
  memcpy((char*) &address->sin_addr.s_addr, 
        hostInfo->h_addr_list[0],
        hostInfo->h_length);
}

// Checks for bad characters
void validate(const char *buffer){
  if (strspn(buffer, VALID_CHARS) != strlen(buffer)) {
      fprintf(stderr, "enc_client error: input contains bad characters\n");
      exit(1);
  }
}

// Read the plaintext file
char *readFile(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
      fprintf(stderr, "enc_client error: cannot open file %s\n", filename);
      exit(1);
  }
  // Move to end to determine file size.
  if (fseek(fp, 0, SEEK_END) != 0) {
      fprintf(stderr, "enc_client error: fseek error in %s\n", filename);
      exit(1);
  }
  int length = ftell(fp);
  rewind(fp);
  char *buffer = malloc(length + 1);
  fread(buffer, sizeof(char), length, fp);
  fclose(fp);

  buffer[length] = '\0';
  buffer[strcspn(buffer, "\n")] = '\0'; 

  return buffer;
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

int recvAll(int s, char *buf, int *len)
{
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

void sendInt(int socketFD, int value){
  int converted = htonl(value);
  if(send(socketFD, &converted, sizeof(converted), 0) == -1){
    perror("sendInt");
    exit(2);
  }
}

int main(int argc, char *argv[]) {
  int socketFD, charsWritten, charsRead;
  struct sockaddr_in serverAddress;
  char buffer[256];
  // Check usage & args
  if (argc < 4) { 
    fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
    exit(1); 
  }

  // Read files
  char *plaintext = readFile(argv[1]);
  char *key = readFile(argv[2]);

  // Validate plaintext and key
  validate(plaintext);

  if (strlen(key) < strlen(plaintext)) {
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

  int textLen = strlen(plaintext);
  sendInt(socketFD, textLen); 
  if(sendAll(socketFD, plaintext, &textLen) == -1){
    perror("sendAll");
    printf("We only sent %d bytes because of the error!\n", textLen);
    exit(2);
  } 

  int keyLen = strlen(key);
  sendInt(socketFD, keyLen); 
  if(sendAll(socketFD, key, &keyLen) == -1){
    perror("sendAll");
    printf("We only sent %d bytes because of the error!\n", keyLen);
    exit(2);
  }

  char *ciphertext = malloc(textLen + 1);
  if (!ciphertext){
    fprintf(stderr, "enc_client error: allocating memory for ciphertext\n");
    exit(1);
  }

  // Clear out the buffer again for reuse
  memset(ciphertext, '\0', textLen + 1);

  int recvLen = textLen;
  if(recvAll(socketFD, ciphertext, &recvLen) == -1){
      perror("recvAll");
      free(ciphertext);
      exit(1);
  }

  // Prints ciphertext stdout
  fprintf(stdout, "%s\n", ciphertext);
  fflush(stdout);

  free(ciphertext);
  free(plaintext);
  free(key);

  // Close the socket
  close(socketFD); 
  return 0;
}