#include "Server.h"

int main()
{
	srand(time(NULL));
	Server *server;
	server=new Server();
	server->startlisten();
}
