#include <jni.h>
#include <string>
#include <sys/ptrace.h>
#include <jni.h>
#include <string>
#include<iostream>
#include<sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdlib.h>
#include <fcntl.h>
#include "android/log.h"
#include <errno.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <asm/unistd.h>
#include <stdio.h>
#include <Android/log.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdbool.h>

#define LOG_TAG "GToad"
#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args);
#define K 1024
#define WRITELEN (128*K)
#define MAX (128*K)


extern "C"



    unsigned long getLibAddr (const char *lib)
{
    puts ("Enter getLibAddr");
    unsigned long addr = 0;
    char lineBuf[256];

    snprintf (lineBuf, 256-1, "/proc/%d/maps", getpid ());
    FILE *fp = fopen (lineBuf, "r");
    if (fp == NULL) {
        perror ("fopen failed");
        goto bail;
    }
    while (fgets (lineBuf, sizeof(lineBuf), fp)) {
        if (strstr (lineBuf, lib)) {
            char *temp = strtok (lineBuf, "-");
            addr = strtoul (temp, NULL, 16);
            break;
        }
    }
    bail:
    fclose(fp);
    return addr;
}

bool checkBreakPoint ()
{
    __android_log_print(ANDROID_LOG_INFO,"JNI","13838438");
    int i, j;
    unsigned int base, offset, pheader;
    Elf32_Ehdr *elfhdr;
    Elf32_Phdr *ph_t;

    base = getLibAddr ("libnative-lib.so");

    if (base == 0) {
        LOGI ("getLibAddr failed");
        return false;
    }
    __android_log_print(ANDROID_LOG_INFO,"JNI","13838439");

    elfhdr = (Elf32_Ehdr *) base;
    pheader = base + elfhdr->e_phoff;

    for (i = 0; i < elfhdr->e_phnum; i++) {
        ph_t = (Elf32_Phdr*)(pheader + i * sizeof(Elf32_Phdr)); // traverse program header

        if ( !(ph_t->p_flags & 1) ) continue;
        offset = base + ph_t->p_vaddr;
        offset += sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * elfhdr->e_phnum;

        char *p = (char*)offset;
        for (j = 0; j < ph_t->p_memsz; j++) {
            if(*p == 0x01 && *(p+1) == 0xde) {
                LOGI ("Find thumb bpt %p", p);
                return true;
            } else if (*p == 0xf0 && *(p+1) == 0xf7 && *(p+2) == 0x00 && *(p+3) == 0xa0) {
                LOGI ("Find thumb2 bpt %p", p);
                return true;
            } else if (*p == 0x01 && *(p+1) == 0x00 && *(p+2) == 0x9f && *(p+3) == 0xef) {
                LOGI ("Find arm bpt %p", p);
                return true;
            }
            p++;
        }
    }
    return false;
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromTime(
        JNIEnv *env,
        jobject /* this */) {
    long start,end;
    start = clock();
    std::string hello = "Hello from time";
    end = clock();
    if(end-start>10000){
        hello = "Debug from time";
    }
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromFile(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello;
    std::stringstream stream;
    int pid = getpid();
    int fd;
    stream << pid;
    stream >> hello;
    hello = "/proc/" + hello + "/status";
    //LOGI(hello);
    char* pathname = new char[30];
    strcpy(pathname,hello.c_str());
    char* buf = new char[500];
    int flag = O_RDONLY;
    fd = open(pathname, flag);
    read(fd, buf, 500);
    char* c;
    char* tra = "TracerPid";
    c = strstr(buf, tra);
    char* d;
    d = strstr(c,"\n");
    int length = d-c;
    strncpy(buf,c+11,length-11);
    buf[length-11]='\0';
    hello = buf;
    if (strcmp(buf,"0")){
        hello = "Debug from file";
    }
    else{
        hello = "Hello from file";
    }
    close(fd);

    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromTrick(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from trick";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromVm(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from vm";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromPtrace(
        JNIEnv *env,
        jobject /* this */) {
    int check = ptrace(PTRACE_TRACEME,0 ,0 ,0);
    LOGI("ret of ptrace : %d",check);
    std::string hello = "Hello from ptrace";
    if(check != 0){
        hello = "Debug from ptrace";
    }
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromBkpt(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from bkpt";
    if(checkBreakPoint())
        hello = "Debug from bkpt";
    return env->NewStringUTF(hello.c_str());
}

char dynamic_ccode[] = {0x1f,0xb4, //push {r0-r4}
                        0x01,0xde, //breakpoint
                        0x1f,0xbc, //pop {r0-r4}
                        0xf7,0x46};//mov pc,lr

char *g_addr = 0;

void my_sigtrap(int sig){
    LOGI("my_sigtrap\n");

    char change_bkp[] = {0x00,0x46}; //mov r0,r0
    memcpy(g_addr+2,change_bkp,2);
    __builtin___clear_cache(g_addr,(g_addr+8)); // need to clear cache
    LOGI("chang bpk to nop\n");

}

void anti4(){//SIGTRAP

    int ret,size;
    char *addr,*tmpaddr;

    signal(SIGTRAP,my_sigtrap);

    addr = (char*)malloc(PAGE_SIZE*2);

    memset(addr,0,PAGE_SIZE*2);
    g_addr = (char *)(( (long)addr + PAGE_SIZE-1) & ~(PAGE_SIZE-1));

    LOGI("addr: %p ,g_addr : %p\n",addr,g_addr);

    ret = mprotect(g_addr,PAGE_SIZE,PROT_READ|PROT_WRITE|PROT_EXEC);
    if(ret!=0)
    {
        LOGI("mprotect error\n");
        return ;
    }

    size = 8;
    memcpy(g_addr,dynamic_ccode,size);

    __builtin___clear_cache(g_addr,(g_addr+size)); // need to clear cache
    LOGI("start stub\n");

    __asm__("push {r5}\n\t"
            "push {r0-r4,lr}\n\t"
            "mov r0,pc\n\t"  //此时pc指向后两条指令
            "add r0,r0,#6\n\t"//cjh:这里的add是add.w，所以会占32位，因此需要+6才对。 原文：+4 是的lr 地址为 pop{r0-r5}
            "mov lr,r0\n\t"
            "mov pc,%0\n\t"
            "pop {r0-r5}\n\t"
            "mov lr,r5\n\t" //恢复lr
            "pop {r5}\n\t"
    :
    :"r"(g_addr)
    :);

    LOGI("hi, i'm here\n");
    free(addr);
    LOGI("hi, i'm here2\n");

}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromSignal(
        JNIEnv *env,
        jobject /* this */) {
    anti4();
    std::string hello = "Hello from signal";
    return env->NewStringUTF(hello.c_str());
}

//------------------------------------------------fork---------------------------------------------------------------------
int pipefd[2];
int childpid;

void *anti3_thread(void *){

    int statue=-1,alive=1,count=0;

    close(pipefd[1]);

    while(read(pipefd[0],&statue,4)>0)
        break;
    sleep(1);

    //这里改为非阻塞
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK); //enable fd的O_NONBLOCK

    LOGI("pip-->read = %d", statue);

    while(true) {

        LOGI("pip--> statue = %d", statue);
        read(pipefd[0], &statue, 4);
        sleep(1);

        LOGI("pip--> statue2 = %d", statue);
        if (statue != 0) {
            kill(childpid,SIGKILL);
            kill(getpid(), SIGKILL);
            return NULL;
        }
        statue = -1;
    }
}

void anti3(){
    int pid,p;
    FILE *fd;
    char filename[MAX];
    char line[MAX];

    pid = getpid();
    sprintf(filename,"/proc/%d/status",pid);// 读取proc/pid/status中的TracerPid
    p = fork();
    if(p==0) //child
    {
        LOGI("Child");
        close(pipefd[0]); //关闭子进程的读管道
        int pt,alive=0;
        pt = ptrace(PTRACE_TRACEME, 0, 0, 0); //子进程反调试
        while(true)
        {
            fd = fopen(filename,"r");
            while(fgets(line,MAX,fd))
            {
                if(strstr(line,"TracerPid") != NULL)
                {
                    LOGI("line %s",line);
                    int statue = atoi(&line[10]);
                    LOGI("########## tracer pid:%d", statue);
                    write(pipefd[1],&statue,4);//子进程向父进程写 statue值

                    fclose(fd);

                    if(statue != 0)
                    {
                        LOGI("########## tracer pid:%d", statue);
                        return ;
                    }

                    break;
                }
            }
            sleep(1);

        }
    }else{
        LOGI("Father");
        childpid = p;
    }
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_sec_gtoad_antidebug_MainActivity_stringFromFork(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from fork";
    pthread_t id_0;
    id_0 = pthread_self();
    pipe(pipefd);
    pthread_create(&id_0,NULL,anti3_thread,(void*)NULL);
    LOGI("Start");
    anti3();
    /*
    pid_t pid;
    int result = -1;
    int fd[2];
    int nbytes;
    char string[WRITELEN] = "Hello my pipe 2018!";
    char readbuffer[10*K];

    int *write_fd = &fd[1];
    int *read_fd = &fd[0];

    result = pipe(fd);
    if(result==-1)
    {
        LOGI("Fail to create pipe\n");
        hello = "Debug from fork";
    }

    pid = fork();

    if(pid == -1)
    {
        LOGI("Fail to fork");
        hello = "Debug from fork";
    }

    if(pid == 0)
    {
        LOGI("SON");
        int write_size = WRITELEN;
        result = 0;
        close(*read_fd);
        while(write_size>=0)
        {
            result = write(*write_fd,string,write_size);
            if(result>0){
                write_size -= result;
                LOGI("Write %d bytes data, the rest is %d bytes",result, write_size);
            }
            else
            {
                sleep(10);
            }
        }
        return env->NewStringUTF(hello.c_str());
    }
    else
    {
        LOGI("FATHER");
        close(*write_fd);
        while(1)
        {
            nbytes = read(*read_fd,readbuffer,sizeof(readbuffer));
            if(nbytes<=0)
            {
                LOGI("No data to write.");
                break;
            }
            LOGI("receive %d bytes data : %s",nbytes,readbuffer);
        }
        return env->NewStringUTF(hello.c_str());
    }*/

    return env->NewStringUTF(hello.c_str());
}


