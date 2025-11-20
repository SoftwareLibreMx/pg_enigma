-- assignment casts
CREATE CAST (varchar AS Ersa) WITH FUNCTION string_as_ersa AS ASSIGNMENT;
CREATE CAST (text AS Ersa) WITH FUNCTION string_as_ersa AS ASSIGNMENT;
-- typmod workaround cast
CREATE CAST (Ersa AS Ersa) WITH FUNCTION ersa_as_ersa AS IMPLICIT;
