-- assignment casts
CREATE CAST (varchar AS Epgp) WITH FUNCTION string_as_epgp AS ASSIGNMENT;
CREATE CAST (text AS Epgp) WITH FUNCTION string_as_epgp AS ASSIGNMENT;
-- typmod workaround cast
CREATE CAST (Epgp AS Epgp) WITH FUNCTION epgp_as_epgp AS IMPLICIT;
