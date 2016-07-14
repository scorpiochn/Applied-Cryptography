--
-- X.501 The Directory - Models
--
--      Subset of Definitions in Annex C used for
--      Certificates

-- InformationFramework
IF	 DEFINITIONS ::=

BEGIN

SECTIONS        build parse none

AttributeType	::=	OBJECT IDENTIFIER
AttributeValue  ::=     ANY


AttributeValueAssertion ::= 	SEQUENCE {AttributeType, AttributeValue }

Name    ::=     SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeValueAssertion

AttributeValues ::= SET OF AttributeValue
Attribute ::= SEQUENCE {AttributeType, AttributeValues}



END
