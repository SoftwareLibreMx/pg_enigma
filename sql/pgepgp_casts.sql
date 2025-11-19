-- assignment casts
CREATE CAST (varchar AS PgEpgp) WITH FUNCTION string_as_pgepgp AS ASSIGNMENT;
CREATE CAST (text AS PgEpgp) WITH FUNCTION string_as_pgepgp AS ASSIGNMENT;
-- typmod workaround cast
CREATE CAST (PgEpgp AS PgEpgp) WITH FUNCTION pgepgp_as_pgepgp AS IMPLICIT;
