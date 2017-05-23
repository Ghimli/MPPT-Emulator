#ifndef SERVER_H_
#define SERVER_H_

#include <list>
#include "Thread.h"

using namespace std;

class Thread;
class Server {
public:
	list <Thread *> wlist;

	Server();
	~Server();
	void start();
	void startlisten();
};

#endif /* SERVER_H_ */
