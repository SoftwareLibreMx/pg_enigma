-- assignment casts
CREATE CAST (varchar AS Enigma) WITH FUNCTION string_as_enigma AS ASSIGNMENT;
CREATE CAST (text AS Enigma) WITH FUNCTION string_as_enigma AS ASSIGNMENT;
-- typmod workaround cast
CREATE CAST (enigma AS enigma) WITH FUNCTION enigma_as_enigma AS IMPLICIT;
