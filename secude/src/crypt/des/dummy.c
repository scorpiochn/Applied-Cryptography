#include <stdio.h>

main(){
	char x[10000];

	while (scanf("%s\n", x) != EOF)
		printf("%s\n", x);
}
