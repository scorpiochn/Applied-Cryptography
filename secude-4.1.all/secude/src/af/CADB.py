KM      DEFINITIONS ::=

%{      /* surrounding global definitions       */
#include        "cadb.h"
%}

BEGIN
-- EXPORTS
--              SET_OF_IssuedCertificate
--
-- IMPORTS	
--              UTCTime, INTEGER
--			FROM UNIV
--


ENCODER build


IssuedCertificate [[ P IssuedCertificate *]]
    ::=     
        SEQUENCE
        {
            serial
                INTEGER
                [[i parm -> serial ]],

            issuedate
                UTCTime
		[[ s parm->date_of_issue ]]
        }


IssuedCertificateSet [[P SET_OF_IssuedCertificate *]] ::=
        SET OF
            <<; parm; parm = parm -> next>>
            IssuedCertificate
            [[p parm -> element ]]


DECODER parse


IssuedCertificate [[ P IssuedCertificate **]]
    ::= 
        %{
            if ((*(parm) = (IssuedCertificate *)
                    calloc (1, sizeof **(parm))) == ((IssuedCertificate *) 0)) {
                advise (NULLCP, "out of memory");
                return NOTOK;
            }
        %}  
	SEQUENCE 
        {
            serial
                INTEGER
		[[ i (*parm)->serial ]],

	    issuedate
                UTCTime
		[[ s (*parm)->date_of_issue ]]
        }


IssuedCertificateSet [[P SET_OF_IssuedCertificate **]] ::=
        SET OF
            %{
                if ((*(parm) = (SET_OF_IssuedCertificate *)
                        calloc (1, sizeof **(parm))) == ((SET_OF_IssuedCertificate *) 0)) {
                    advise (NULLCP, "out of memory");
                    return NOTOK;
                }
            %}
            IssuedCertificate
            [[p &((*parm) -> element)]]
            %{ parm = &((*parm) -> next); %}

END
