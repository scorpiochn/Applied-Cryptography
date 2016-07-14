#include <stdio.h>
main() {
        char b[512], fn[128];
        register char *bb, *dd, *cc;
        char a;
        char *fgets();
        FILE *out = (FILE *)0;

	while(1) {
	        bb = fgets(b, sizeof(b), stdin);
         	if(!bb || strlen(bb) == 0) break;
                if(strncmp(b, "\\nm{", 4) == 0) {
                        if(strncmp(&b[8], "af", 2) == 0) a = 'a';
                        if(strncmp(&b[8], "sec", 3) == 0) a = 's';
                        dd = &b[4];
                        cc = fn;
                        while(*dd != '}') *cc++ = *dd++;
                        *cc++ = '.';
                        while(*dd != '{') dd++;
                        dd ++;
                        while(*dd != '}') if(*dd != '*' && *dd != '/') *cc++ = *dd++; else { *cc++ = a; dd++; }
                        *cc = '\0';
                        fclose(out);
                        if(!(out = fopen(fn, "w"))) exit(-1);
                }
                if(out) fprintf(out, "%s", b);
        }
	exit(0);
}
