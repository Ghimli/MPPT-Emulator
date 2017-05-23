#include <pthread.h>
#include <stdio.h>
#include <sys/timeb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <list>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "Server.h"
#include "Thread.h"
using namespace std;

#define PORT 9330

void startpthread(void *p)
{
	((Thread *)p)->start();
}

Server::Server()
{

}

Server::~Server()
{
}

void Server::startlisten()
{
	start();
}

void Server::start()
{
	int sock;
	int one=1,connected;
	struct sockaddr_in server_addr, client_addr;
	unsigned int sin_size;
	Thread *thread;
	pthread_t child;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (int)) == -1) {
		perror("Setsockopt");
		exit(1);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero((void *)(&(server_addr.sin_zero)), 8);

	if (bind(sock, (struct sockaddr *) &server_addr, sizeof (struct sockaddr))
			== -1) {
		perror("Unable to bind");
		exit(1);
	}

	if (listen(sock, 100) == -1) {
		perror("Listen");
		exit(1);
	}
	printf("Server Waiting for client on port %d\n",PORT);
	sin_size = sizeof (struct sockaddr_in);
	while (1)
	{
		connected = accept(sock, (struct sockaddr *) &client_addr, &sin_size);
		if (connected>0)
		{
			thread=new Thread(this);
			thread->fd=connected;
			pthread_create(&child, NULL, (void*(*)(void *))startpthread, thread);
			pthread_detach(child);
		}else usleep(5000);
	}
}
