#include <unistd.h>
int main(int argc, char **argv){
    char *n[64];
    int k=0;
    n[k++]="./iomap"; n[k++]=MODE; n[k++]="./readfile";
    for(int i=1;i<argc && k<62;i++) n[k++]=argv[i];
    n[k]=0;
    execv("./iomap", n);
    return 127;
}
