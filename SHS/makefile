
# Comment the following line if your compiler doesn't support prototyping

PROTO=-DPROTO

FLAGS=$(PROTO) -O

shs:	shsdrvr.o shs.o
	$(CC) $(FLAGS) -o shs shsdrvr.o shs.o
	strip shs

shsdrvr.o:	shsdrvr.c shs.h
	$(CC) $(FLAGS) -c shsdrvr.c

shs.o:	shs.c shs.h
	$(CC) $(FLAGS) -c shs.c

clean:
	rm -f shs shs.o shsdrvr.o

