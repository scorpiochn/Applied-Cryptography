char *usage_msg[] = {
#ifdef RIPEMSIG
 "ripemsig: {Riordan's|RSAREF-based} Internet Privacy Enhanced Mail, v.1.2a",
 "*** Exportable signature-only version ***",
 "Signs/verifies mail messages using RSA and MD5, and generates keys.",
#else
 "ripem: {Riordan's | RSAREF-based} Internet Privacy Enhanced Mail, v.1.2a",
 "Encrypts/decrypts mail messages using RSA and DES, and generates keys.",
#endif
 "ripem is in the public domain, but requires agreeing to the RSAREF license ",
 "from RSA Data Security; contact rsaref-info@rsa.com.  It's free but limited.",
 "ripem was written by Mark Riordan (mrr@scss3.cl.msu.edu).  See doc for credits.  ",
 "Usage:  ripem {-e | -d | -g | -c}     <in >out",
#ifdef RIPEMSIG
 "  [-r recipient] [-m {mic-only | mic-clear}]",
#else
 "  [-r recipient] [-m {encrypted | mic-only | mic-clear}]",
#endif
 "  [-u myusername]  [-h head] [-b #_of_bits_in_gen_key]",
 "  [-p publickey_infile(s)] [-s privatekey_infile] [-k key_to_private_key or -]",
 "  [-P publickey_outfile] [-S privatekey_outfile] [-A enc_alg]",
 "  [-y pub_key_server_name] [-Y key_sources] [-T recip_opts]",
 "  [-i infile] [-o outfile] [-D debug_level] [-Z debug_out_file]          ",
 "  [-R random_sources] [-F random_input_file] [-C random_string]         ",
 "  [-v #_of_validity_months] [-K new_key_to_private_key] [-H home_dir]   ",
 "where:",
 "  enc_alg is the encryption algorithm:  des-cbc (default) or des-ede-cbc.",
 "  key_sources is a string of one or more of \"fgs\", which tell ripem to look",
 "    for public keys from a File, finGer, or Server, in the order specified.",
 "  head is one or more of \"ipr\", for Include headers in msg; Prepend headers",
 "    to output; get Recipients from headers.  ",
 "  random_sources is one or more of \"cefkms\", specifying \"random\" input from",
 "    Command line, Entire command, File, Keyboard, Message, or running System.",
 "  recip_opts is one or more of \"amn\", for Abort if can't find keys for",
 "    all users; include Me as a recipient if encrypting; None of the above.",
 "Relevant environment variables:   RIPEM_HOME_DIR,",
 "  RIPEM_PUBLIC_KEY_FILE, RIPEM_PRIVATE_KEY_FILE, RIPEM_KEY_TO_PRIVATE_KEY,",
 "  RIPEM_USER_NAME, RIPEM_RANDOM_FILE, RIPEM_SERVER_NAME, RIPEM_ARGS",
(char *)0
};
