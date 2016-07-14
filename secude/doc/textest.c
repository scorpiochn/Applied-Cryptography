#include <stdio.h>

/*    Zeilennummer und Inhalt der Zeile, in der die erste ungeschlossene '{' steht, 
 *     --> stdout.
 *    Parameter: Filenames
 */

struct kl {
        char *klauf;
        char *klzu;
        int auf;
        int toomany;
        int linex;
        int linenr;
        char *linebuf;
} kl[] = { "{", "}", 0, 0, 0, 0, (char *)0,
           "(", ")", 0, 0, 0, 0, (char *)0,
           "[", "]", 0, 0, 0, 0, (char *)0,
           "\\begin", "\\end", 0, 0, 0, 0, (char *)0 
};
int anzkl = sizeof(kl) / sizeof(kl[0]);

main(argn, argv) 
int argn;
char *argv[];
{
        register int i;
        int line, n, err = 0, b[5], bi;
        FILE *ff = (FILE *)0;
        char buf[5][512];
        register char *dd, *bb, *back, *diff;
        register struct kl *x, *y, *xa = &kl[0], *xe = &kl[anzkl], *xee = &kl[anzkl-1];

        if(argn == 1) {argn++; ff = stdin;}
        for(n = 1; n < argn; n++) {
                dd = bb = buf[0];
                bi = 0;
                back = diff = (char *)0;
                line = 1;
                for(x = xa; x < xe; x++) {
                        x->linebuf = dd;
                        x->linex = 0;
                        x->auf = 0;
                        x->toomany = 0;
                }
                for(i = 1; i < anzkl + 1; i++) b[i] = 0;
                b[0] = 1;
sec:
                if(!ff) if(!(ff = fopen(argv[n], "r"))) {
                        printf("Can't open %s\n", argv[n]);
                        continue;
                }
                while((i = getc(ff)) != EOF) {
/*                        putchar(i); */
                        if(i == '\012') {
                                *dd++ = i;
                                *dd = '\0';
                                for(x = xa; x < xe; x++) {
                                        if(x->toomany) {
                                                printf("Zu viele %s in %s Zeile %d:\n", x->klzu, argv[n], line);
                                                printf("%s", bb);
                                        }
                                        x->toomany = 0;
                                }
                                for(i = 0; i < anzkl + 1; i++) if(b[i] == 0) {
                                        dd = bb = buf[i];
                                        bi = i;
                                }
                                else b[i] = 0;
                                line++;
                                for(x = xa; x < xe; x++) if(x->auf == 0) {
                                        x->linex = bi;
                                        x->linebuf = bb;
                                        x->linenr = line;
                                        b[bi] = 1;
                                }
                                else b[x->linex] = 1;
                                back = (char *)0;
                        }
                        else {
                                diff++;
                                *dd++ = i;
                                *dd = '\0';
                                if(i == '\\') {
                                        back = dd - 1;
                                        diff = (char *)0;
                                        continue;
                                }
                                for(x = xa; x < xee; x++) {
                                        if(i == x->klauf[0]) (x->auf)++;
                                        if(i == x->klzu[0]) {
                                                (x->auf)--;
                                                if(x->auf < 0) {
                                                        x->toomany = 1; 
                                                        x->auf = 0;
                                                }
                                        }
                                }
                                if(diff == (char *)3 || diff == (char *)5) {
                                        x = &kl[anzkl-1];
                                        if(back && strcmp(back, x->klauf) == 0) (x->auf)++;
                                        if(back && strcmp(back, x->klzu) == 0) {
                                                (x->auf)--;
                                                if(x->auf < 0) {
                                                        x->toomany = 1; 
                                                        x->auf = 0;
                                                }
                                        }
                                }
                        }
                }
                fclose(ff);
                for(x = xa; x < xe; x++) {
                        if(x->auf) {
                                err = -1;
                                printf("Nichtgeschlossene %s in %s Zeile %d:\n", x->klauf, argv[n], x->linenr);
                                printf("%s", x->linebuf);
                        }
                }
nextfile:
                ff = (FILE *)0;
        }
        exit(err);
}
