#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const char keyChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
int max = 27;

int main(int argc, char *argv[]){
    int keylength;

    if(argc != 2){
        fprintf(stderr, "Usage: %s <keylength>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    keylength = atoi(argv[1]);

    // Seed for random number generator
    srand(time(NULL));

    // Creates a keyfile of specified length
    for (int i = 0; i < keylength; i++){
        int index = rand() % max;
        fprintf(stdout, "%c", keyChars[index]);
    }

    // Last character of keygen is a newline
    fprintf(stdout, "\n");

    exit(EXIT_SUCCESS);
}