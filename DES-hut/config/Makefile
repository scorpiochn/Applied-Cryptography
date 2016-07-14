CC=cc
LDFLAGS=-Llibdir 
CFLAGS=-O -Ilibdir 
LIBS=
ELIBS=
OBJS=config.o
PROGS=config
all:	$(PROGS)
config:	config.o $(LIBS)
	$(CC) $(LDFLAGS) -o config config.o $(LIBS) $(ELIBS)
clean::
	rm -f $(PROGS) $(OBJS)
