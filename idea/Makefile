all: idea

crypt.o:	crypt.h crypt.c
	-cc -I. -c crypt.c

idea.o:	idea.c crypt.h
	-cc -I. -c idea.c

idea:	idea.o crypt.o
	-cc -o idea idea.o crypt.o
#
#	if you use 'pixrect' (for raster files), add 'rasterAndTime'
#	definition in idea.c
#
#	-cc -o idea idea.o crypt.o -lpixrect
