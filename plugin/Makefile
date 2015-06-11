CC=             gcc

CFLAGS =        -g -Wall -fPIC -g -Wall -D_GNU_SOURCE 
CFLAGS+=        -std=c99
CFLAGS+=        `pkg-config --cflags glib-2.0`
CFLAGS+=        `pkg-config --cflags gthread-2.0`
CFLAGS+=        `pkg-config --cflags openssl`

LDFLAGS =        -shared -lhiredis -levent
LDFLAGS+=	`pkg-config --libs glib-2.0`
LDFLAGS+=	`pkg-config --libs gthread-2.0`
LDFLAGS+=	`pkg-config --libs openssl`

SRCS=		re_redis_mod.c redis_storage.c
OBJECTS=	$(SRCS:.c=.o) 

BINSO=		rtpengine-redis.so

all:	$(SRCS) $(BINSO)

rtpengine:
	cd ../rtpengine/daemon && $(MAKE)

$(BINSO): $(OBJECTS) 
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

rtpengine-redis:      $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJECTS) $(BINSO) core core.*
