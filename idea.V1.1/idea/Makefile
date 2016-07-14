# make          is used to build user command 'idea'
# make raster   is used to build a user command 'idea' that is capable to 
#               encrypt and decrypt rasterfiles (pictures on SUN computers)
# make test     is used to test correctness of user command 'idea'
# make lint     is used for debugging
#
# If 'ANSI_C' is defined in 'idea.h' then the preprocessed source code is
# ANSI-C or C++ code, otherwise it is Kerninghan & Ritchie C code.
#
# change the next line such that your C-compiler is used
CC      = acc -O2

all:	idea

idea:	idea_cmd.c idea.c idea.h
	$(CC) -o idea idea_cmd.c idea.c

raster:	idea_cmd.c idea.c idea.h
	$(CC) -DRASTERFILE -DTIME -o idea idea_cmd.c idea.c

test:	idea dumphex.c idea.h
	$(CC) -o dumphex dumphex.c
	test1

lint:	idea_cmd.c idea.c idea.h
	alint -abchx idea_cmd.c idea.c
