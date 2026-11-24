/* iomap <off|remap|remap-mask> <prog> [args...]
 *
 * A syscall-level I/O path mapper, in the family of fakeroot / path-remapping
 * sandboxes: it runs a child under ptrace and can rewrite which file an open()
 * actually hits, and optionally mask the bytes a read() returns. It writes an
 * out-of-band audit line for every remap to iomap_truth.jsonl.
 *
 * Modes:
 *   off         passthrough (honest execution)
 *   remap       rewrite open() of public/report.txt -> private/keys.txt
 *   remap-mask  remap, and replace the bytes read from the mapped fd with the
 *               bytes of public/report.txt (so the caller observes the file it
 *               named, while a different file was actually opened and read)
 *
 * x86-64 Linux only. Single traced child (the given prog); that is all this demo
 * needs. The audit log is the ground truth for what physically happened.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>

static const char *MAPPED_FROM = "public/report.txt";
static const char *MAPPED_TO   = "private/keys.txt";
static const char *AUDIT       = "iomap_truth.jsonl";

static char benign[512];
static size_t benign_len = 0;

static void load_benign(void){
    int fd = open(MAPPED_FROM, O_RDONLY);
    if(fd>=0){ int n=read(fd,benign,sizeof(benign)); if(n>0) benign_len=(size_t)n; close(fd); }
}

static void audit(const char *syscall, const char *requested, const char *actual,
                  long real_ret, long returned, const char *tampered){
    FILE *f=fopen(AUDIT,"a");
    if(!f) return;
    fprintf(f,"{\"ts\":%ld,\"syscall\":\"%s\",\"requested\":\"%s\",\"actual\":\"%s\",",
            (long)time(NULL), syscall, requested, actual);
    if(real_ret!=-999) fprintf(f,"\"real_ret\":%ld,\"returned\":%ld,", real_ret, returned);
    fprintf(f,"\"tampered\":\"%s\"}\n", tampered);
    fclose(f);
}

static void read_str(pid_t pid, unsigned long addr, char *out, size_t max){
    size_t i=0;
    while(i<max-1){
        errno=0;
        long word=ptrace(PTRACE_PEEKDATA,pid,addr+i,0);
        if(word==-1 && errno) break;
        memcpy(out+i,&word,sizeof(word));
        for(size_t j=0;j<sizeof(word);j++) if(out[i+j]==0){ return; }
        i+=sizeof(word);
    }
    out[max-1]=0;
}

static void write_mem(pid_t pid, unsigned long addr, const char *src, size_t len){
    size_t i=0;
    for(; i+sizeof(long)<=len; i+=sizeof(long)){
        long word; memcpy(&word, src+i, sizeof(long));
        ptrace(PTRACE_POKEDATA,pid,addr+i,word);
    }
    if(i<len){
        long word=0; size_t rem=len-i;
        /* preserve nothing beyond; zero-pad the tail word */
        memcpy(&word, src+i, rem);
        ptrace(PTRACE_POKEDATA,pid,addr+i,word);
    }
}

int main(int argc, char **argv){
    if(argc<3){ fprintf(stderr,"usage: iomap <off|remap|remap-mask> <prog> [args...]\n"); return 2; }
    const char *mode=argv[1];
    int do_remap = strcmp(mode,"remap")==0 || strcmp(mode,"remap-mask")==0;
    int do_mask  = strcmp(mode,"remap-mask")==0;
    if(do_mask) load_benign();

    pid_t child=fork();
    if(child==0){
        ptrace(PTRACE_TRACEME,0,0,0);
        raise(SIGSTOP);
        execv(argv[2], &argv[2]);
        _exit(127);
    }
    int status; waitpid(child,&status,0);
    ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL);

    int entry=1;
    long sysno=0;
    int   arm_fd_track=0;      /* this open was remapped; capture its fd at exit */
    long  tracked_fd=-1;       /* fd to mask reads on */
    int   pending_scrub=0;
    unsigned long scrub_addr=0;
    char  last_requested[512]={0};

    while(1){
        if(ptrace(PTRACE_SYSCALL,child,0,0)<0) break;
        if(waitpid(child,&status,0)<0) break;
        if(WIFEXITED(status)) break;
        /* only act on syscall-stops */
        if(!(WIFSTOPPED(status) && (WSTOPSIG(status)==(SIGTRAP|0x80)))) continue;

        struct user_regs_struct r;
        ptrace(PTRACE_GETREGS,child,0,&r);

        if(entry){
            sysno=r.orig_rax;
            if(sysno==SYS_openat && do_remap){
                char path[512]; read_str(child,r.rsi,path,sizeof(path));
                if(strstr(path,MAPPED_FROM)){
                    strncpy(last_requested,path,sizeof(last_requested)-1);
                    write_mem(child,r.rsi,MAPPED_TO,strlen(MAPPED_TO)+1);
                    audit("openat",path,MAPPED_TO,-999,0,"remap");
                    if(do_mask) arm_fd_track=1;
                }
            } else if(sysno==SYS_read && do_mask && (long)r.rdi==tracked_fd){
                pending_scrub=1; scrub_addr=r.rsi;
            }
            entry=0;
        } else {
            if(sysno==SYS_openat && arm_fd_track){
                if((long)r.rax>=0) tracked_fd=r.rax;
                arm_fd_track=0;
            } else if(sysno==SYS_read && pending_scrub){
                long real_ret=(long)r.rax;
                write_mem(child,scrub_addr,benign,benign_len);
                r.rax=benign_len;
                ptrace(PTRACE_SETREGS,child,0,&r);
                audit("read",last_requested,"returned public/report.txt bytes",
                      real_ret,(long)benign_len,"content-mask");
                pending_scrub=0;
                tracked_fd=-1; /* one-shot */
            }
            entry=1;
        }
    }
    return 0;
}
