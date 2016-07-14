typedef struct {
  int	len;
  char	*data;
  int	echar;
  int	(*getcf)();
} hut_linebuf;

extern int	errno;

extern hut_linebuf	hut_linebuf_z;

extern char	*malloc();
extern char	*realloc();
extern char	*index();
extern char	*rindex();
extern int	getopt();
extern char	*optarg;
extern int	optind;
extern char	*strerror();
extern char	*getenv();

extern char	*hut_next_field();
extern char	*hut_getline();
extern char	*hut_getpass();
extern char	*hut_read_password();
extern char	*hut_alloc();
extern char	*hut_realloc();
extern int	hut_free();
extern char	*hut_strsave();

#define HUT_NEW(type) ((type*)malloc(sizeof(type)))
#define HUT_NEW_CHECK(type) ((type*)hut_alloc(sizeof(type)))

#define HUT_NEW_ARR(type,n) ((type*)malloc((n)*sizeof(type)))
#define HUT_NEW_ARR_CHECK(type,n) ((type*)hut_alloc((n)*sizeof(type)))

#ifdef __STDC__
#define GLUE(a,b) a##b
#else
#define GLUE(a,b) a/**/b
#endif
