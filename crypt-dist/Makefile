SUBDIRS=config hutlib alodes mp
all:	FORCE
	for j in $(SUBDIRS); do ( cd $$j; make ); done
clean::	FORCE
	for j in $(SUBDIRS); do ( cd $$j; make clean ); done
FORCE:
