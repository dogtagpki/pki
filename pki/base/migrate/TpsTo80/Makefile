OS_ARCH := $(subst /,_,$(shell uname -s))

ifeq ($(OS_ARCH), Linux)
	CC = gcc
	CFLAGS = -g 
	LDFLAGS = -s -lldif60  -lplc4 -lplds4 -lnspr4
else
ifeq ($(OS_ARCH), SunOS)
	CC = cc
	LINTFLAGS = -c
	CFLAGS = -dalign -xO2 -xarch=v9 -DSOLARIS
	INCLUDE_PATH = -I/usr/include/dirsec
	LDFLAGS = -s -L/usr/lib/64 -lldif60 -L/usr/lib/64/dirsec -R/usr/lib/64/dirsec -lplc4 -lplds4 -lnspr4
endif # SunOS
endif # Linux

OBJS = migrateTPSData.o

SRCS = migrateTPSData.c

all: migrateTPSData

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDE_PATH) -c $< \
	-o $*.o

migrateTPSData: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

lint: $(SRCS)
	lint $(LINTFLAGS) $(CFLAGS) $(INCLUDE_PATH) $(SRCS)

clean:
	-rm migrateTPSData.ln
	-rm migrateTPSData.o
	-rm migrateTPSData
