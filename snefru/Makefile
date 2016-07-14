##
##  This is Snefru, derived from the Xerox Secure Hash Function.
##  Snefru is a one-way hash function that provides authentication.
##  It does not provide secrecy.
##
##  Snefru is named after a Pharaoh of ancient Egypt.
##
##  It is based on code that is:
##      Copyright (c) Xerox Corporation 1989.  All rights reserved.
##
##      License to copy and use this software is granted provided that it
##      is identified as the 'Xerox Secure Hash Function' in all material
##      mentioning or referencing this software or this hash function.
##
##      License is also granted to make and use derivative works provided
##      that such works are identified as 'derived from the Xerox Secure
##      Hash Function' in all material mentioning or referencing the
##      derived work.
##
##      Xerox Corporation makes no representations concerning either the
##      merchantability of this software or the suitability of this
##      software for any particular purpose.  It is provided "as is"
##      without express or implied warranty of any kind.
##
##      These notices must be retained in any copies of any part of this
##      software.
##
##  Based on the reference implementation (no algorithm changes) of
##  version 2.0, July 31, 1989.  Implementor:  Ralph C. Merkle.
##  This edition is by Rich $alz, <rsalz@bbn.com>.
##  $Header: Makefile,v 1.1 90/03/22 12:57:52 rsalz Exp $
##

##  Add -DUSE_STRCHR here if you use strchr/strrchr.
##  Add -DCHARPSPRINTF here if you need "extern char *sprinf();"
DEFS	= -DCHARPSPRINTF
CFLAGS	= $(DEFS) -O
#CFLAGS	= $(DEFS) -g


##
all:		snefru testboxes hashnews checkhash

install:	all
	@echo Install according to local convention

clean:
	rm -f foo core tags lint* a.out tests *.o Part0?
	rm -f snefru testboxes hashnews checkhash testboxes.c

tests:		all tests.sh lint
	@rm -f $@
	sh ./tests.sh | tee tests

shar:
	makekit -m -t "Now see the README"

##
snefru.o hash512.o sboxes.o:		snefru.h
testboxes.o hashn.o hash512.o:		snefru.h
checkhash.o hashnews.o pipeit.o:	snefru.h

testboxes.c:	testboxes.c1 testboxes.c2
	@rm -f $@
	cat testboxes.c1 testboxes.c2 >$@

##
snefru:		snefru.o hash512.o sboxes.o
	@rm -f $@
	$(CC) $(CFLAGS) -o $@ snefru.o hash512.o sboxes.o

testboxes:	testboxes.o hashn.o hash512.o sboxes.o
	@rm -f $@
	$(CC) $(CFLAGS) -o $@ testboxes.o hashn.o hash512.o sboxes.o

checkhash:	checkhash.o pipeit.o
	$(CC) $(CFLAGS) -o $@ checkhash.o pipeit.o

hashnews:	hashnews.o pipeit.o
	$(CC) $(CFLAGS) -o $@ hashnews.o pipeit.o

##
lint:		lint.s lint.t lint.h lint.c

lint.s:		snefru
	@rm -f $@
	lint -b -h $(DEFS) snefru.c hash512.c sboxes.c >$@
lint.t:		testboxes
	@rm -f $@
	lint -b -h $(DEFS) testboxes.c hashn.c hash512.c sboxes.c >$@
lint.c:		checkhash
	@rm -f $@
	lint -b -h $(DEFS) checkhash.c pipeit.c >$@
lint.h:		hashnews
	@rm -f $@
	lint -b -h $(DEFS) hashnews.c pipeit.c >$@
