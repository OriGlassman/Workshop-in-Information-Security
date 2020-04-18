#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <string.h>

#define CONN_DEVICE_FILE_PATH "/sys/class/fw/conns/conns_mitm"
#define BUFF_SIZE (100)

/*
* Interacts with the kernel-space in order to get the man in the middile port of a connection
*/
unsigned short get_mitm_port(unsigned int src_ip, char* src_port, unsigned int dst_ip, char* dst_port){
    unsigned short mitm_port; char buff[BUFF_SIZE+1] = {0};
    int fd = open(CONN_DEVICE_FILE_PATH, O_WRONLY);

    if (fd == -1){
        return 1;
    }
    snprintf(buff, BUFF_SIZE, "get %u %s %u %s\n", src_ip, src_port, dst_ip, dst_port);
    mitm_port = write(fd, buff, strlen(buff));
    close(fd);
    return ntohs(mitm_port);
}

/*
* Interacts with the kernel-space in order to set the man in the middile port of a connection
*/
unsigned short set_mitm_port(unsigned int src_ip, char* src_port, unsigned int dst_ip, char* dst_port, char* mitm_port){
    char buff[BUFF_SIZE+1] = {0};
    int res;

    int fd = open(CONN_DEVICE_FILE_PATH, O_WRONLY);
    if (fd == -1){
        return 1;
    }

    snprintf(buff, BUFF_SIZE, "set %u %s %u %s %s\n", src_ip, src_port, dst_ip, dst_port, mitm_port);
    res = write(fd, buff, strlen(buff));
    close(fd);
    if (res == 1 || res == -1){
        printf("Problem occurred setting mitm port\n");
        return res;
    } else {
        return 0;
    }
}

/*
* Interacts with the kernel-space in order to create the ftp-data connections
*/
unsigned short create_ftp_entries(unsigned int src_ip, char* data_port, unsigned int dst_ip, char* dst_port){
    char buff[BUFF_SIZE+1] = {0};
    int res;

    int fd = open(CONN_DEVICE_FILE_PATH, O_WRONLY);
    if (fd == -1){
        return 1;
    }

    snprintf(buff, BUFF_SIZE, "create %u %s %u %s\n", src_ip, data_port, dst_ip, dst_port);
    res = write(fd, buff, strlen(buff));
    close(fd);
    if (res != 0){
        printf("Problem occurred creating new ftp data connection entries\n");
        return res;
    } else {
        return 0;
    }
}