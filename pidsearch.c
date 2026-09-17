#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/select.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
    FLAG_NONE            = 0,
    FLAG_SHELL           = 1 << 0,
    FLAG_SOCKET_STDIN    = 1 << 1,
    FLAG_SOCKET_STDOUT   = 1 << 2,
    FLAG_SOCKET_STDERR   = 1 << 3,
    FLAG_OUTBOUND_TCP    = 1 << 4,
    FLAG_SUSPICIOUS_CMD  = 1 << 5,
    FLAG_ODD_PARENT      = 1 << 6
}ProcessFlag;

typedef struct {
    pid_t pid;
    unsigned int flags;
    int riskScore;
} ProcessInfo;

int WaitInput() {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO,&readfds);
    struct timeval timeout;
    timeout.tv_sec =2;
    timeout.tv_usec =0;
    int result = select(
        STDIN_FILENO+1,
        &readfds,
        NULL,
        NULL,
        &timeout
    );
    if(result > 0){
        char input[32];
        ssize_t bytes = read(STDIN_FILENO,input,sizeof(input));
        if(bytes == 0){
            return 0;
        }
        if(bytes > 0){
            for(ssize_t i =0;i<bytes;i++){
                if((i == 0 || input[i-1] == '\n') &&
                    (input[i] == 'q' || input[i] == 'Q')){
                    return 0;
                }
            }
        }
    }
    if(result < 0 && errno != EINTR){
        perror("select");
        return 0;
    }
    return 1;
}

int ReadStatusInt(pid_t pid,const char *field) {
    if(field == NULL || *field == '\0'){
        return -1;
    }
    char buffer[256];
    char ProcessName[256];
    snprintf(buffer,sizeof(buffer),"/proc/%d/status",pid);
    FILE *statfile = fopen(buffer,"r");
    if(statfile == NULL){
        return -1;
    }
    size_t fieldLength = strlen(field);
    while(fgets(ProcessName,sizeof(ProcessName),statfile)!=NULL){
        if(strncmp(ProcessName,field,fieldLength)==0){
            char *end;
            errno =0;
            long value = strtol(ProcessName+fieldLength,&end,10);
            if(errno != 0 || end == ProcessName+fieldLength || value < 0 || value > INT_MAX){
                fclose(statfile);
                return -1;
            }
            fclose(statfile);
            return (int)value;
        }
    }
    fclose(statfile);
    return -1;
}

int ReadComm(pid_t pid,char *ProcessName,size_t ProcessNameSize) {
    if(ProcessName == NULL || ProcessNameSize < 2 || ProcessNameSize > INT_MAX){
        return -1;
    }
    ProcessName[0] = '\0';
    char buffer[256];
    snprintf(buffer,sizeof(buffer),"/proc/%d/comm",pid);
    FILE *file = fopen(buffer,"r");
    if(file == NULL){
        return -1;
    }
    if(fgets(ProcessName,ProcessNameSize,file)==NULL){
        fclose(file);
        return -1;
    }
    ProcessName[strcspn(ProcessName,"\n")] = '\0';
    fclose(file);
    return 0;
}

int ReadCmdline(pid_t pid,char *Cmdline,size_t CmdlineSize) {
    if(Cmdline == NULL || CmdlineSize < 2){
        return -1;
    }
    Cmdline[0] = '\0';
    char buffer[256];
    snprintf(buffer,sizeof(buffer),"/proc/%d/cmdline",pid);
    FILE *file = fopen(buffer,"r");
    if(file == NULL){
        return -1;
    }
    size_t bytes = fread(Cmdline,1,CmdlineSize-1,file);
    fclose(file);
    if(bytes == 0){
        Cmdline[0] = '\0';
        return -1;
    }
    Cmdline[bytes] = '\0';
    for(size_t i =0;i+1<bytes;i++){
        if(Cmdline[i]=='\0'){
            Cmdline[i] = ' ';
        }
    }
    return 0;
}

int ReadExe(pid_t pid,char *Exe,size_t ExeSize) {
    if(Exe == NULL || ExeSize < 2){
        return -1;
    }
    Exe[0] = '\0';
    char buffer[256];
    snprintf(buffer,sizeof(buffer),"/proc/%d/exe",pid);
    ssize_t bytes = readlink(buffer,Exe,ExeSize-1);
    if(bytes == -1){
        return -1;
    }
    Exe[bytes] = '\0';
    return 0;
}

int ReadFd(pid_t pid,int fd,char *FdValue,size_t FdValueSize) {
    if(FdValue == NULL || FdValueSize < 2){
        return -1;
    }
    FdValue[0] = '\0';
    char buffer[256];
    snprintf(buffer,sizeof(buffer),"/proc/%d/fd/%d",pid,fd);
    ssize_t bytes = readlink(buffer,FdValue,FdValueSize-1);
    if(bytes == -1){
        return -1;
    }
    FdValue[bytes] = '\0';
    return 0;
}

int IsSocketFd(pid_t pid,int fd) {
    char FdValue[256];
    if(ReadFd(pid,fd,FdValue,sizeof(FdValue))==-1){
        return 0;
    }
    if(strncmp(FdValue,"socket:[",8)==0){
        return 1;
    }
    return 0;
}

int TcpTableHasSocket(pid_t pid,const char *table,unsigned long long inode) {
    char buffer[256];
    char line[1024];
    snprintf(buffer,sizeof(buffer),"/proc/%d/net/%s",pid,table);
    FILE *file = fopen(buffer,"r");
    if(file == NULL){
        return 0;
    }
    while(fgets(line,sizeof(line),file)!=NULL){
        char remote[80];
        unsigned int state;
        unsigned long long value;
        if(sscanf(line," %*s %*s %79s %x %*s %*s %*s %*s %*s %llu",
            remote,&state,&value)!=3 || state != 1 || value != inode){
            continue;
        }
        char *colon = strchr(remote,':');
        if(colon == NULL){
            continue;
        }
        char *end;
        unsigned long port = strtoul(colon+1,&end,16);
        int hasAddress =0;
        for(char *point =remote;point<colon;point++){
            if(*point != '0'){
                hasAddress =1;
            }
        }
        if(*end == '\0' && port > 0 && hasAddress){
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

int HasEstablishedTcp(pid_t pid) {
    char buffer[256];
    snprintf(buffer,sizeof(buffer),"/proc/%d/fd",pid);
    DIR *ProcDirectory = opendir(buffer);
    if(ProcDirectory == NULL){
        return 0;
    }
    struct dirent *entry;
    int found =0;
    while((entry = readdir(ProcDirectory))!=NULL){
        char *end;
        errno =0;
        long fd = strtol(entry->d_name,&end,10);
        if(errno != 0 || end == entry->d_name || *end != '\0' || fd < 0 || fd > INT_MAX){
            continue;
        }
        char FdValue[256];
        unsigned long long inode;
        int consumed =0;
        if(ReadFd(pid,(int)fd,FdValue,sizeof(FdValue)) == 0 &&
            sscanf(FdValue,"socket:[%llu]%n",&inode,&consumed) == 1 &&
            consumed > 0 && FdValue[consumed] == '\0' &&
            (TcpTableHasSocket(pid,"tcp",inode) || TcpTableHasSocket(pid,"tcp6",inode))){
            found =1;
            break;
        }
    }
    closedir(ProcDirectory);
    return found;
}

int CalculateRiskScore(unsigned int flags) {
    int sockets =0;
    int riskScore =0;
    if(flags & FLAG_SOCKET_STDIN){
        sockets+=1;
    }
    if(flags & FLAG_SOCKET_STDOUT){
        sockets+=1;
    }
    if(flags & FLAG_SOCKET_STDERR){
        sockets+=1;
    }
    if(flags & FLAG_SHELL){
        riskScore+=1;
    }
    if(sockets == 1){
        riskScore +=1;
    }else if(sockets >= 2){
        riskScore +=4;
    }
    if((flags & FLAG_SHELL) && sockets >= 2){
        riskScore +=2;
    }
    if(flags & FLAG_OUTBOUND_TCP){
        if(sockets >= 2){
            riskScore+=2;
        }else{
            riskScore+=1;
        }
    }
    if(flags & FLAG_SUSPICIOUS_CMD){
        riskScore +=1;
    }
    if(flags & FLAG_ODD_PARENT){
        riskScore +=1;
    }
    return riskScore;
}

int main() {
    while(1){
        DIR *ProcDirectory = opendir("/proc");
        if(ProcDirectory == NULL){
            perror("Proc acilamadi");
            if(WaitInput()==0){
                break;
            }
            continue;
        }
        ProcessArray data;
        ProcessArray *ptr =&data;
        data.PidNum =0;
        size_t pleaseBeEnough =36;
        PidValue *pid_ptr = malloc(sizeof(PidValue)*pleaseBeEnough);
        if(pid_ptr == NULL){
            closedir(ProcDirectory);
            perror("malloc");
            return EXIT_FAILURE;
        }
        struct dirent *entry;
        char *end;
        int incomplete =0;
        while((entry = readdir(ProcDirectory))!=NULL){
            errno =0;
            long IsNumberValue = strtol(entry->d_name,&end,10);
            if(errno == 0 && end != entry->d_name && *end == '\0' &&
                IsNumberValue > 0 && IsNumberValue <= INT_MAX){
                if(ptr->PidNum == INT_MAX){
                    incomplete =1;
                    break;
                }
                if((size_t)ptr->PidNum >= pleaseBeEnough){
                    if(pleaseBeEnough > SIZE_MAX/2/sizeof(PidValue)){
                        incomplete =1;
                        break;
                    }
                    size_t capacity = pleaseBeEnough*2;
                    PidValue *temp = realloc(pid_ptr,capacity*sizeof(PidValue));
                    if(temp == NULL){
                        incomplete =1;
                        break;
                    }
                    pid_ptr = temp;
                    pleaseBeEnough = capacity;
                }
                pid_ptr[ptr->PidNum].PidValue = (int)IsNumberValue;
                ptr->PidNum+=1;
            }
        }
        closedir(ProcDirectory);
        if((size_t)ptr->PidNum > SIZE_MAX/sizeof(ProcessInfo)){
            free(pid_ptr);
            return EXIT_FAILURE;
        }
        ProcessInfo *setFlagsFpid = NULL;
        if(ptr->PidNum > 0){
            setFlagsFpid = malloc(sizeof(ProcessInfo)*(size_t)ptr->PidNum);
            if(setFlagsFpid == NULL){
                free(pid_ptr);
                perror("malloc");
                return EXIT_FAILURE;
            }
        }
        int point =0;
        int displayed =0;
        if(isatty(STDOUT_FILENO)){
            printf("\033[2J\033[H");
        }
        printf("Process Detector\n------------------------------\n");
        if(incomplete){
            printf("PID list incomplete: allocation/capacity limit.\n");
        }
        for(int i =0;i<ptr->PidNum;i++){
            pid_t pid = pid_ptr[i].PidValue;
            char ProcessName[256];
            char Cmdline[4096];
            char Exe[4096];
            setFlagsFpid[point].pid = pid;
            setFlagsFpid[point].flags = FLAG_NONE;
            setFlagsFpid[point].riskScore =0;
            if(ReadComm(pid,ProcessName,sizeof(ProcessName))==-1){
                continue;
            }
            if(strcmp(ProcessName,"bash") == 0 || strcmp(ProcessName,"sh") == 0 ||
                strcmp(ProcessName,"zsh") == 0){
                setFlagsFpid[point].flags |= FLAG_SHELL;
            }
            if(IsSocketFd(pid,0)){
                setFlagsFpid[point].flags |= FLAG_SOCKET_STDIN;
            }
            if(IsSocketFd(pid,1)){
                setFlagsFpid[point].flags |= FLAG_SOCKET_STDOUT;
            }
            if(IsSocketFd(pid,2)){
                setFlagsFpid[point].flags |= FLAG_SOCKET_STDERR;
            }
            ReadStatusInt(pid,"PPid:");
            ReadExe(pid,Exe,sizeof(Exe));
            if(ReadCmdline(pid,Cmdline,sizeof(Cmdline)) == 0 &&
                ((strstr(Cmdline,"/dev/tcp/") && strstr(Cmdline," -i")) ||
                 (strstr(Cmdline,"socket") && strstr(Cmdline,"dup2")))){
                setFlagsFpid[point].flags |= FLAG_SUSPICIOUS_CMD;
            }
            if(HasEstablishedTcp(pid)){
                setFlagsFpid[point].flags |= FLAG_OUTBOUND_TCP;
            }
            setFlagsFpid[point].riskScore = CalculateRiskScore(setFlagsFpid[point].flags);
            if(setFlagsFpid[point].riskScore >= 4){
                for(char *name =ProcessName;*name;name++){
                    if((unsigned char)*name < 32 || (unsigned char)*name == 127){
                        *name = '?';
                    }
                }
                printf("PID: %d | Name: %s | RiskScore: %d\n",
                    pid,ProcessName,setFlagsFpid[point].riskScore);
                displayed+=1;
            }
            point+=1;
        }
        if(displayed == 0){
            printf("No processes above display threshold.\n");
        }
        printf("------------------------------\n");
        printf("[ENTER] Refresh | [Q + ENTER] Exit\nAutomatic refresh: 2 seconds\n");
        fflush(stdout);
        free(setFlagsFpid);
        free(pid_ptr);
        if(WaitInput()==0){
            break;
        }
    }
    return 0;
}
