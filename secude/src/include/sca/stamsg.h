/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAPAC  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	STAMOD			VERSION 2.0	       */
/*					   DATE Januar 1992    */
/*					     BY Levona Eckstein*/
/*						Ursula Viebeg  */ 
/*							       */
/*    FILENAME			                 	       */
/*      stamsg.h    		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains the error messages of STAMOD        */
/*	STAPAC Application Interface         		       */
/*-------------------------------------------------------------*/


/*---------------------------------------------------------------------*/
/* Structur and initialization of stamod_error                         */
/*---------------------------------------------------------------------*/
static struct {
    char msg[128];
} stamod_error[] = {
/* sta_errno/Message                                 */
{/*150*/"STA: no error  "},
{/*151*/"STA: invalid alarm value  "},
{/*152*/"STA: invalid PIN/PUK  "},
{/*153*/"STA: invalid time  "},
{/*154*/"STA: invalid text length  "},
{/*155*/"STA: output data not correct  "},
{/*156*/"STA: input data not correct  "},
{/*157*/"STA: security mode(s) not correct  "},
{/*158*/"STA: invalid key attributes  "},
{/*159*/"STA: invalid level for an RSA key "},
{/*160*/"STA: invalid KeyDevPurpose parameter "},
{/*161*/"STA: key from keycard not installed in SCT "},
{/*162*/"STA: wrong hash_par  "},
{/*163*/"STA: mixed function calls not allowed  "},
{/*164*/"STA: hash-function error  "},
{/*165*/"STA: wrong parameter value"},
{/*166*/"STA: key invalid "},
{/*167*/"STA: illegal value of auth-proc-id "},
{/*168*/"STA: illegal value of auth-object-id "},
{/*169*/"STA: file empty or first record identifier not found"},
{/*170*/"STA: illegal transfer mode "},
{/*171*/"STA: NULL pointer "},
{/*172*/"STA: illegal value of data_struc"},
{/*173*/"STA: more parameter invalid "},
{/*174*/"STA: "},
{/*175*/"STA: "},
{/*176*/"STA: "},
{/*177*/"STA: "},
{/*178*/"STA: "},
{/*179*/"STA: "},
{/*180*/"STA: "},
{/*181*/"STA:   "},
{/*182*/"STA: memory error  "},

};






