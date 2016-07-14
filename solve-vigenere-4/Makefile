CC=gcc
CFLAGS=-O

all: solvevig builddig alfaonly

clean: 
	rm -f *.o solvevig builddig alfaonly *.out core

SOLVE_R=solvevig.o usage.o rdditbl.o
BUILDD_R=builddig.o usage.o rdditbl.o
ALFAO_R=alfaonly.o


solvevig: $(SOLVE_R)
	$(CC) $(CFLAGS) -o solvevig $(SOLVE_R)
	
builddig: $(BUILDD_R)
	$(CC) $(CFLAGS) -o builddig $(BUILDD_R)

alfaonly: $(ALFAO_R)
	$(CC) $(CFLAGS) -o alfaonly $(ALFAO_R)
	
makedigs: builddig
	alfaonly <plainin.txt | builddig | sort -n -r +1 >digrams

testvig: solvevig
	time solvevig -S 1000 -s -w /usr/dict/words -c comp-sup-17 -d digrams  >guesses.out
	

