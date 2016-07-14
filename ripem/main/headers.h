/*--- headers.h ------------------------------ */

#define HEADER_STRING_BEGIN  		"-----BEGIN PRIVACY-ENHANCED MESSAGE-----"
#define HEADER_STRING_END    		"-----END PRIVACY-ENHANCED MESSAGE-----"
#define PUB_KEY_STRING_BEGIN 		"-----BEGIN PUBLIC KEY-----"
#define PUB_KEY_STRING_END   		"-----END PUBLIC KEY-----"
#define PRIV_KEY_STRING_BEGIN 	"-----BEGIN PRIVATE KEY-----"
#define PRIV_KEY_STRING_END   	"-----END PRIVATE KEY-----"

#define PROC_TYPE_FIELD       	"Proc-Type:"
#define CONTENT_DOMAIN_FIELD   	"Content-Domain:"
#define DEK_FIELD             	"DEK-Info:"
#define SENDER_FIELD          	"Originator-Name:"
#define SENDER_PUB_KEY_FIELD  	"Originator-Key-Asymmetric:"
#define ORIGINATOR_CERT_FIELD  	"Originator-Certificate:"
#define RECIPIENT_FIELD       	"Recipient-Name:"
#define RECIPIENT_KEY_FIELD    	"Recipient-Key-Asymmetric:"
#define MESSAGE_KEY_FIELD     	"Key-Info:"
#define MIC_INFO_FIELD				"MIC-Info:"
#define UNREC_FIELD					NULL

#define PROC_TYPE_ENCRYPTED_ID	"ENCRYPTED"
#define PROC_TYPE_MIC_ONLY_ID		"MIC-ONLY"
#define PROC_TYPE_MIC_CLEAR_ID	"MIC-CLEAR"
#define MIC_MD2_ID               "RSA-MD2"
#define MIC_MD5_ID					"RSA-MD5"
#define ENCRYPTION_ALG_RSA_ID		"RSA"
#define PROC_TYPE_RIPEM_ID   		"2001"
#define PROC_TYPE_PEM_ID	   		"4"
#define DEK_ALG_DES_CBC_ID    	"DES-CBC"
#define DEK_ALG_TDES_CBC_ID    	"DES-EDE-CBC"
#define UNREC_ID						NULL

#define SPEC_SEP		         ","


#define DEF_FIELDS(mac) \
	mac(PROC_TYPE),mac(CONTENT_DOMAIN),mac(DEK),mac(SENDER),     \
	mac(SENDER_PUB_KEY),mac(ORIGINATOR_CERT),mac(RECIPIENT),mac(RECIPIENT_KEY),mac(MESSAGE_KEY),    \
	mac(MIC_INFO),mac(UNREC)

#define DEF_IDS(mac) \
	mac(PROC_TYPE_ENCRYPTED_ID),   \
	mac(PROC_TYPE_MIC_ONLY_ID),    \
	mac(PROC_TYPE_MIC_CLEAR_ID),       \
	mac(MIC_MD2_ID),               \
	mac(MIC_MD5_ID),               \
	mac(ENCRYPTION_ALG_RSA_ID),    \
	mac(PROC_TYPE_RIPEM_ID),       \
	mac(PROC_TYPE_PEM_ID),       \
	mac(DEK_ALG_DES_CBC_ID),       \
	mac(DEK_ALG_TDES_CBC_ID),       \
	mac(UNREC_ID)

#ifdef __STDC__
#define MAKE_ENUM(val) val##_ENUM
#define MAKE_TEXT(val) val##_FIELD
#define MAKE_IDS(val)  val
#else
#define MAKE_ENUM(val) val/**/_ENUM
#define MAKE_TEXT(val) val/**/_FIELD
#define MAKE_IDS(val)  val
#endif

enum enum_fields { DEF_FIELDS(MAKE_ENUM) };
enum enum_ids { DEF_IDS(MAKE_ENUM) };

DEF char *FieldNames[]
#ifdef MAIN
= { DEF_FIELDS(MAKE_TEXT) }
#endif
;

DEF char *IDNames[]
#ifdef MAIN
= { DEF_IDS(MAKE_IDS) }
#endif
;

