#include <asm-generic/errno.h>
#define WORK_PC "Linux"
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

typedef struct {
    int PidNum;
}ProcessArray;
typedef struct{
    int PidValue;
}PidValue;
typedef struct {
    const char *comm;
    const char *status;
    const char *cmdline;
    const char *exe;
    const char *fd;
    const char *tcp;
    const char *tcp6;
} ProcPaths;
typedef enum {
    FLAG_NONE           = 0,
    FLAG_SHELL          = 1 << 0,
    FLAG_SOCKET_STDIN   = 1 << 1,
    FLAG_SOCKET_STDOUT  = 1 << 2,
    FLAG_SOCKET_STDERR  = 1 << 3,
    FLAG_OUTBOUND_TCP   = 1 << 4,
    FLAG_SUSPICIOUS_CMD = 1 << 5,
    FLAG_ODD_PARENT     = 1 << 6
}ProcessFlag;

typedef struct {
    pid_t pid;
    unsigned int flags;
    int riskScore;
} ProcessInfo;


int main() {
    ProcPaths paths = {
    .comm    = "/proc/%d/comm",
    .status  = "/proc/%d/status",
    .cmdline = "/proc/%d/cmdline",
    .exe     = "/proc/%d/exe",
    .fd      = "/proc/%d/fd",
    .tcp     = "/proc/net/tcp",
    .tcp6    = "/proc/net/tcp6"
    };
    ProcessInfo *setFlagsFpid;
	DIR *ProcDirectory = opendir("/proc");
    errno =0;
    ProcessArray data;
    ProcessArray *ptr =&data;
    data.PidNum =0;
    PidValue Pids;
    PidValue *pid_ptr = &Pids;
    if(ProcDirectory == NULL){
        switch(errno){
            case EACCES:
                return EACCES;
                break;
            case ENOENT:
                struct utsname ptr;
                    if(uname(&ptr) == 0){
                        if(strcmp(ptr.sysname,WORK_PC) != 0){
                            perror("This program using linux\n");
                        }else{}
                    }
                break;
                }
        }
    else {}
    struct dirent *entry;
    pid_t pid= getpid();
    int i =0;
    char *end;
    pid_ptr = malloc(sizeof(int)*36);
    size_t pleaseBeEnough = 36;
    while((entry = readdir(ProcDirectory))!=NULL){
        long IsNumberValue = strtol(entry->d_name,&end,10);
        if(end != entry->d_name && *end == '\0' && IsNumberValue > 0)
        {
            ptr->PidNum+=1;
            pid_ptr[i].PidValue = IsNumberValue;
            i++;
        }
    }
    if(ptr->PidNum > pleaseBeEnough){
        pleaseBeEnough *=2;
        PidValue *temp = realloc(pid_ptr,pleaseBeEnough*sizeof(PidValue));
        if (temp == NULL){
            perror("Bellek Hatası\n");
        }
        else {
            temp = pid_ptr;
        }
    }
    for(int i =0;i<ptr->PidNum;i++){
        printf("%d\n",pid_ptr[i].PidValue);
    }
    char buffer[pleaseBeEnough];
    char ProcessName[256];
    int point =0;
    for(int i =0;i<pleaseBeEnough;i++){
        snprintf(buffer,sizeof(buffer),"/proc/%d",pid_ptr[i].PidValue);
        DIR *dir =opendir(buffer);
        snprintf(buffer,sizeof(buffer),paths.comm,pid_ptr[i].PidValue);
        FILE *file = fopen(buffer,"r");
        if (file != NULL){
            if(fgets(ProcessName,sizeof(ProcessName),file)!=NULL)
            {
                printf("PID: %d -> Name: %s\n",pid_ptr[i].PidValue,ProcessName);
                ProcessName[strcspn(ProcessName,"\n")] = '\0';
                if(strcmp(ProcessName,"bash")==0){
                    point+=1;
                    setFlagsFpid = malloc(sizeof(ProcessInfo)*point);
                    if (setFlagsFpid == NULL)
                    {
                        printf("Bellek hatası ilgili process yansıtılıyor\n");
                    }
                    printf("Şüpheli Pid => %d İsmi => %s\n",pid_ptr[i].PidValue,ProcessName);
                    setFlagsFpid[i].pid = pid_ptr[i].PidValue;
                    setFlagsFpid[i].flags |= FLAG_SHELL;
                    snprintf(buffer,sizeof(buffer),paths.status,pid_ptr[i].PidValue);
                    FILE *statfile = fopen(buffer,"r");
                    if (statfile !=NULL)
                    {
                        while(fgets(statfile,sizeof(statfile),statfile)!=NULL)
                        {
                            if(strncmp(statfile,"PPid:",5) ==NULL)
                            {
                                long ppid = strtol(statfile+5,NULL,10);
                                printf("Parent id =>%ld\n",ppid);
                                break;
                            }
                        }
                    }
                    fclose(statfile);
                }

            }
            fclose(file);
        }
    }
    printf("My process name->%d\n",pid);
    printf("%d\n",ptr->PidNum);
    closedir(ProcDirectory);
    return 0;
}
