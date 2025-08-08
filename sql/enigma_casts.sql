-- CREATE CAST (char AS Enigma) WITH FUNCTION char_as_enigma AS ASSIGNMENT;
CREATE CAST (varchar AS Enigma) 
	WITH FUNCTION enigma_assignment_cast AS ASSIGNMENT;
CREATE CAST (text AS Enigma) 
	WITH FUNCTION enigma_assignment_cast AS ASSIGNMENT;
CREATE CAST (enigma AS enigma) WITH FUNCTION enigma_cast AS IMPLICIT;
