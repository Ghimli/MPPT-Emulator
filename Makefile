CFLAGS := -g -std=c++11
CF := 
LIBS := -lpthread -lcrypto
PROG := MPPTEmulator
OBJS := mppt.o Server.o Thread.o key.o

all: $(PROG)

$(PROG): $(OBJS)
	g++ $(CFLAGS) -Wall -Wextra -Wformat -Wformat-security -fno-stack-protector -fstack-protector-all -Wstack-protector -D_FORTIFY_SOURCE=2 -Wl,--gc-sections -o $@ $^ $(LIBS)

%.o: %.cpp 
	g++ $(CFLAGS) $(CF) -c -Wall -Wextra -Wformat -Wformat-security -fno-stack-protector -fstack-protector-all -Wstack-protector -D_FORTIFY_SOURCE=2 -ffunction-sections -fdata-sections -o $@ $<

clean:
	rm -f *.o $(PROG)
