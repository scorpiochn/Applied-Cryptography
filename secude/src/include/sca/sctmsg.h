
/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	SCTINT			VERSION 2.0	       */
/*					   DATE November 1991  */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME			                 	       */
/*      sctmsg.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all error messages from the SCT-    */
/*	interface modules        			       */
/*-------------------------------------------------------------*/
#include "sctloc.h"
SCTerror sct_error[TABLEN] = {
/*       SW1          SW2           Message                                 */
{/*  0*/0x10,        0,            "T: not defined"                },
{/*  1*/0x00,        0x20,         "T: Read error"                     },
{/*  2*/0x00,        0x21,         "T: Write error"                         },
{/*  3*/0x00,        0x22,         "T: EDC-Error       "                    },
{/*  4*/0x00,        0x23,         "T: Memory error   "                     },
{/*  5*/0x00,        0x24,         "T: Open error "                         },
{/*  6*/0x00,        0x25,         "T: Close error "                        },
{/*  7*/0x00,        0x26,         "T: BWT - Timeout"                       },
{/*  8*/0x00,        0x27,         "T: CWT - Timeout       "                },
{/*  9*/0x00,        0x28,         "T: Invalid length"                      },
{/* 10*/0x00,        0x29,         "T: Length of TPDU-request is too long"  },
{/* 11*/0x00,        0x30,         "T: port not available"                  },
{/* 12*/0x00,        0x31,         "T: Error from system call"             },
{/* 13*/0x00,        0x32,         "T: Protocol has been resynchronized"   },
{/* 14*/0x00,        0x33,         "T: SCT should be reset "               },
{/* 15*/0x00,        0x34,         "T: Block Format Error"                 },
{/* 16*/0x10,        0,            "T: not defined"                        },
{/* 17*/0x10,        0,            "T: not defined"                        },
{/* 18*/0x10,        0,            "T: not defined"                        },
{/* 19*/0x10,        0,            "T: not defined"                        },
/*                                                                    */
{/* 20*/0x41,        0x00,         "SCT: CLASS-Byte invalid   "             },
{/* 21*/0x41,        0x01,         "SCT: INS-Code invalid                "  },
{/* 22*/0x41,        0x02,         "SCT: Key-ID invalid   "                 },
{/* 23*/0x41,        0x03,         "SCT: Algorithm Identifier invalid "     },
{/* 24*/0x41,        0x04,         "SCT: Operation mode invalid       "     },
{/* 25*/0x41,        0x05,         "SCT: Parameter in body missing         "},
{/* 26*/0x41,        0x06,         "SCT: Parameter in body incorrect       "},
{/* 27*/0x41,        0x07,         "SCT: Data-Length incorrect        "     },
{/* 28*/0x41,        0x08,         "SCT: User Input incorrect         "   },
{/* 29*/0x41,        0x09,         "SCT: P1 / P2 incorrect            "   },
{/* 30*/0x41,        0x0A,         "SCT: data length level 2 incorrect   "   },
{/* 31*/0x41,        0x0B,         "SCT: communication counter incorrect"   },
/*                                                                    */
{/* 32*/0x42,        0x00,         "SCT: Specified key not found "          },
{/* 33*/0x42,        0x01,         "SCT: Key and algorithm inconsistent  " },
{/* 34*/0x42,        0x02,         "SCT: Not allowed to replace existing key"},
{/* 35*/0x42,        0x03, "SCT: Key-Information from keycard incorrect"},
/*                                                                    */
{/* 36*/0x43,        0x00,         "SCT: error not defined            "      },
{/* 37*/0x43,        0x01,         "SCT: Transfer of SC-Command not allowed" },
{/* 38*/0x43,        0x02,         "SCT: Length of ciphertext incorrect"     },
{/* 39*/0x43,        0x03,         "SCT: Signature invalid            "      },
{/* 40*/0x43,        0x04,         "SCT: Key-Length invalid           "      },
{/* 41*/0x43,        0x05,         "SCT: no memory available          "      },
{/* 42*/0x43,        0x06,      "SCT: Authentication with Smartcard failed"  },
{/* 43*/0x43,        0x07,         "SCT: RESET of SCT not successful       "},
{/* 44*/0x43,        0x08,         "SCT: Execution denied                  "},
{/* 45*/0x43,        0x09,         "SCT: Service not available (e.g. RSA key generation)  "},
{/* 46*/0x43,        0x0A,         "SCT: Secure messaging key undefined    "},
{/* 47*/0x43,        0x0B,         "SCT: Authentication key undefined      "},
/*                                                                    */
{/* 48*/0x44,        0x00,         "SCT: No Smartcard in SCT          "     },
{/* 49*/0x44,        0x01,         "SCT: RESET of SC not successful   "     },
{/* 50*/0x44,        0x02,         "SCT: Smartcard removed            "     },
{/* 51*/0x44,        0x03,         "SCT: Timeout - no answer from SC  "     },
{/* 52*/0x44,        0x04,         "SCT: Break from user              "     },
{/* 53*/0x44,        0x05,         "SCT: Timeout - no answer from user"     },
/*                                                                    */
{/* 54*/0x45,        0x00,         "SCT: internal addressing error"    },
{/* 55*/0x10,        0,            "SCT: not defined"                  },
{/* 56*/0x10,        0,            "SCT: not defined"                  },
{/* 57*/0x10,        0,            "SCT: not defined"                  },
{/* 58*/0x10,        0,            "SCT: not defined"                  },
{/* 59*/0x90,        0x03,         "SC: Data inconsistent or internal security policy violated or no data found"},
/*                                                                   */
{/* 60*/0x6E,        0x00,         "SC: wrong CLASS-Byte             "    },
{/* 61*/0x6D,        0x00,         "SC: wrong INS-Code               "    },
{/* 62*/0x6F,        0x00,         "SC: EEPROM-Write Error while FCB update    "   },
{/* 63*/0x6F,        0x01,         "SC: command aborted (Vcc error)  "    },
{/* 64*/0x6F,        0x02,         "SC: command aborted (Compare error)"   },
{/* 65*/0x6B,        0x00,         "SC: invalid parameter P1 or P2 "    },
{/* 66*/0x6B,        0x01,         "SC: Filestructure incorrect or LOCK-Command on ISF,ACF or PEF not allowed "    },
{/* 67*/0x67,        0x01,    "SC: LENGTH and/or POS incorrect          " },
{/* 68*/0x67,        0x02,  "SC: Length of the input data is different from the record length or SPACE-value incorrect" },
{/* 69*/0x67,        0x03,    "SC: Length of the output data is too long" },
{/* 70*/0x67,        0x04,         "SC: invalid length of the body   " },
{/* 71*/0x67,        0x05,         "SC: parameter in body wrong or SPACE-value incorrect     "    },
/*                                                                    */
{/* 72*/0x50,        0x00,         "SC: Error of the internal security policy "    },
{/* 73*/0x50,        0x01,         "SC: command not allowed          "    },
/*                                                                   */
{/* 74*/0x50,        0x02,         "SC: command not described in ACF or not allowed in actual state "    },
{/* 75*/0x50,        0x03,         "SC: access from sublayer not allowed"    },
/*                                                                   */
{/* 76*/0x50,        0x04,         "SC: access denied by EF ACV"    },
{/* 77*/0x91,        0x01,         "SC: address error          "    },
{/* 78*/0x91,        0x03,         "SC: error while ACF access"    },
{/* 79*/0x00,        0x00,         "SC: undetected ECC error  "    },
{/* 80*/0x00,        0x51,         "SC: system error          "    },
{/* 81*/0x92,        0x01,         "SC: system error          "    },
{/* 82*/0x92,        0x02,         "SC: File exists already   "   },
{/* 83*/0x92,        0x03,         "SC: required space not available "    },
{/* 84*/0x92,        0x05,         "SC: RID exists already "   },
/*                                                                    */
{/* 85*/0x94,        0x01,         "SC: DF not registered or command after create EF not allowed"   },
{/* 86*/0x94,        0x02,         "SC: File not found "   },
{/* 87*/0x94,        0x03,         "SC: RID not found or invalid      "   },
{/* 88*/0x94,        0x04,         "SC: ACF not found                 "   },
{/* 89*/0x94,        0x05,    "SC: Command or Parameters inconsistent with File Type"},
{/* 90*/0x94,        0x06,         "SC: Master File not active        "   },
{/* 91*/0x94,        0x07,         "SC: general error                 "   },
/*                                                                    */
{/* 92*/0x98,        0x01,         "SC: invalid key selection         "   },
{/* 93*/0x98,        0x02,         "SC: key locked                    "   },
{/* 94*/0x98,        0x03,         "SC: Length of PIN incorrect or PUK-record refers to no PIN-record"   },
{/* 95*/0x98,        0x04,         "SC: NEW PIN incorrect             "   },
{/* 96*/0x98,        0x05,         "SC: access denied                 "   },
{/* 97*/0x98,        0x06,         "SC: authentication failed or write access denied        "   },
{/* 98*/0x98,        0x07,         "SC: wrong algorithm                     "   },
{/* 99*/0x98,        0x08,         "SC: EDC error on key record"   },
{/*100*/0x98,        0x09,         "SC: key fault presentation counter incorrect "   },
{/*101*/0x98,        0x0A,         "SC: no secure messaging key defined "   },
{/*102*/0x98,        0x0B,         "SC: wrong send sequence counter (SC)"   },
{/*103*/0x98,        0x0C,         "SC: wrong MAC                       "   },
{/*104*/0x98,        0x0D,         "SC: key fault presentation counter run down  "   },
/*                                                                    */
{/*105*/0x00,        105,     "SCTL: invalid argument            "   },
{/*106*/0x00,        106,     "SCTL: no available memory         "   },
{/*107*/0x00,        107,     "SCTL: invalid devicenumber        "   },
{/*108*/0x00,        108,     "SCTL: APDU too long or length of parameter invalid"   },
{/*109*/0x00,        109,     "SCTL: no shell variable STAMOD in env " },
{/*110*/0x00,        110,     "SCTL: can't open Installation File    " },
{/*111*/0x00,        111,     "SCTL: no record in Installation File  " },
{/*112*/0x00,        112,     "SCTL: Installation File not successfully closed"},
{/*113*/0x00,        113,     "SCTL: Read error on Installation File     "},
{/*114*/0x00,        114,     "SCTL: SCT-ID unknown                      "},
{/*115*/0x00,        115,     "SCTL: Length error                        "},
{/*116*/0x00,        116,     "SCTL: Baudvalue not allowed (< 2400)      "},
{/*117*/0x00,        117,     "SCTL: Data can`t be encrypted             "},
{/*118*/0x00,        118,     "SCTL: Data can`t be decrypted             "},
{/*119*/0x00,        119,     "SCTL: Can't generate sessionkey           "},
{/*120*/0x00,        120,     "SCTL: Error after RSA encryption          "},
{/*121*/0x00,        121,     "SCTL: Can't set RSA key            "},
{/*122*/0x00,        122,     "SCTL: wrong send sequence counter from SCT"   },
{/*123*/0,           0,       "SCTL: Error number not defined    "}};

