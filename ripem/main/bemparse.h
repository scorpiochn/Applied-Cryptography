/*--- bemparse.h --------------------------------------*/
#include "p.h"

typedef int TypeClass;
typedef long int TypeTag;
typedef long int TypeLength;
typedef int      TypeConstructed;

typedef unsigned char octet;

/* Function Prototypes. */
TypeLength ParseID P((unsigned char **octstr, TypeClass *class,
  TypeConstructed *constructed, TypeTag *tag));
TypeLength BEMParse P((unsigned char *octstr, FILE *stream));
TypeLength BEMParse2 P((unsigned char **octstr));
void ParseSequence P((unsigned char **octstr, TypeLength length));
TypeLength ParseLength P((octet **octstr, TypeLength *length));
void PutIndent P((void));

/*--- End of bemparse.h --------------------------------*/
