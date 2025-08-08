CREATE CAST (Enigma AS Enigma) 
	WITH FUNCTION enigma_cast AS IMPLICIT;
CREATE CAST (Text AS Enigma) 
	WITH FUNCTION cast_text_as_enigma AS IMPLICIT;
