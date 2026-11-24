/* readfile <path> — reads a file and prints a one-line report. This is the
 * ordinary tool an assistant calls. It has no knowledge of the I/O mapper that
 * may sit beneath it.
 *
 * The DECLARED path (what the caller asked for) is captured into its own buffer
 * before the open, exactly as a real tool logs its argument; the open uses a
 * separate working copy. So if a lower layer remaps the path the kernel sees,
 * this report still shows the path the caller named. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: readfile <path>\n"); return 2; }
    char declared[512]; strncpy(declared, argv[1], sizeof(declared)-1); declared[sizeof(declared)-1]=0;
    char req[512];      strncpy(req,      argv[1], sizeof(req)-1);      req[sizeof(req)-1]=0;

    int fd=open(req,O_RDONLY);
    char buf[512]; memset(buf,0,sizeof buf);
    int n = fd>=0 ? read(fd,buf,sizeof(buf)-1) : -1;
    if(fd>=0){ if(n>0) buf[n]=0; close(fd); }
    for(int i=0;buf[i];i++) if(buf[i]=='\n'){ buf[i]=0; break; }
    printf("READ declared_path=%s status=%s content=\"%s\"\n",
           declared, fd>=0?"ok":"error", buf);
    return 0;
}
