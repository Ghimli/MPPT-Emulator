#ifndef THREAD_H_
#define THREAD_H_

#include <list>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mysql/mysql.h>
#include <json-c/json.h>
#include "Server.h"

#define MAXBUF 100

using namespace std;

class Server;
class Thread {
public:
	Server *server;
	int fd;

	Thread(Server *);
	~Thread();
	void start();
};

#endif /* THREAD_H_ */
