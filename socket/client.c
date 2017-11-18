#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUF_LEN 128
#define NUM_PORTS 5

#define LOG_PATH "log"
#define SERVER_IP "192.168.56.102"

typedef struct socket_ad {
	int port;
	int fd;
} SocketAd;

const int ports[NUM_PORTS] = {
  4444, 5555, 6666, 7777, 8888
};



// connect to the server
// using TCP/IP
// for each port given
void connectToServer(SocketAd* socks) {
  struct sockaddr_in server_addr;
	int i;

  for (i = 0; i < NUM_PORTS; i++) {
    // socekt creation failed?
    if ( (socks[i].fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
      printf("Client%d : Can't open stream socket\n", i);
      exit(0);
    }

    memset(&server_addr, 0x00, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(socks[i].port);

    // connection failed?
    if ( connect(socks[i].fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 ) {
      printf("Client%d : Can't connect to server.\n", i);
      exit(0);
    }
    printf("Port %d: Connected", socks[i].port);
  }

  return;
}

// read data from
// server until it stops
void* readServer(void* socket_param) {
  SocketAd* sock = (SocketAd*)socket_param;
  FILE* fp;
  char logfile_name[10];
  char logfile_path[20] = LOG_PATH;
  char buffer[BUF_LEN];
  int msg_size, i;
  struct timeval t_rec;
	struct tm* tm;

  // write log file
	sprintf(logfile_name, "/%d.txt", sock->port);
	strcat(logfile_path, logfile_name);
	fp = fopen(logfile_path, "w");

  // read until stop
  while ( (msg_size = read(sock->fd, buffer, BUF_LEN)) > 0 ) {
		// get current time
    gettimeofday(&t_rec, NULL);
		tm = localtime(&t_rec.tv_sec);

		printf("%d port reading...\n", sock->port);
    fprintf(fp, "%d:%d:%d.%d %d %s\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(t_rec.tv_usec % 1000),
			msg_size, buffer);
		// is this necessary?
		// memset(buffer, 0, sizeof(buffer));
  }
  close(sock->fd);
  fclose(fp);

  return NULL;
}


int main(int argc, char* argv[]) {
  SocketAd socks[NUM_PORTS];
  pthread_t pthreads[NUM_PORTS];
  void* val;
	int i;

  // assign ports to each socket
  for (i = 0; i < NUM_PORTS; i++) {
    socks[i].port = ports[i];
  }

  connectToServer(socks);

  // make a log directory to save log files
  mkdir(LOG_PATH, 0755);

  // fork a thread for each port
  // to perform an operation
  for (i = 0; i < NUM_PORTS; i++) {
    pthread_create(&pthreads[i], NULL, readServer, (void*)&socks[i]);
  }

  // close up pthreads created
  for (i = 0; i < NUM_PORTS; i++) {
    pthread_join(pthreads[i], &val);
  }

  return 0;
}
