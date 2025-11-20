--
-- PostgreSQL database dump
--

\restrict IKADtaQJVk1VYEADMPxNc8lVXL16lAobuEkq6Y7jsCCiVjfM2UFILgiKJnh2hHM

-- Dumped from database version 13.22
-- Dumped by pg_dump version 13.22

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_enigma; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_enigma WITH SCHEMA public;


--
-- Name: EXTENSION pg_enigma; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_enigma IS 'pg_enigma:  Created by pgrx';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: test_both; Type: TABLE; Schema: public; Owner: sandino
--

CREATE TABLE public.test_both (
    id integer NOT NULL,
    val1 public.enigma(2),
    val2 public.enigma(3)
);


ALTER TABLE public.test_both OWNER TO sandino;

--
-- Name: test_both_id_seq; Type: SEQUENCE; Schema: public; Owner: sandino
--

CREATE SEQUENCE public.test_both_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.test_both_id_seq OWNER TO sandino;

--
-- Name: test_both_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sandino
--

ALTER SEQUENCE public.test_both_id_seq OWNED BY public.test_both.id;


--
-- Name: test_epgp; Type: TABLE; Schema: public; Owner: sandino
--

CREATE TABLE public.test_epgp (
    id integer NOT NULL,
    val public.epgp(2)
);


ALTER TABLE public.test_epgp OWNER TO sandino;

--
-- Name: test_epgp_id_seq; Type: SEQUENCE; Schema: public; Owner: sandino
--

CREATE SEQUENCE public.test_epgp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.test_epgp_id_seq OWNER TO sandino;

--
-- Name: test_epgp_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sandino
--

ALTER SEQUENCE public.test_epgp_id_seq OWNED BY public.test_epgp.id;


--
-- Name: test_ersa; Type: TABLE; Schema: public; Owner: sandino
--

CREATE TABLE public.test_ersa (
    id integer NOT NULL,
    val public.ersa(3)
);


ALTER TABLE public.test_ersa OWNER TO sandino;

--
-- Name: test_ersa_id_seq; Type: SEQUENCE; Schema: public; Owner: sandino
--

CREATE SEQUENCE public.test_ersa_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.test_ersa_id_seq OWNER TO sandino;

--
-- Name: test_ersa_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sandino
--

ALTER SEQUENCE public.test_ersa_id_seq OWNED BY public.test_ersa.id;


--
-- Name: test_pgp; Type: TABLE; Schema: public; Owner: sandino
--

CREATE TABLE public.test_pgp (
    id integer NOT NULL,
    val public.enigma(2)
);


ALTER TABLE public.test_pgp OWNER TO sandino;

--
-- Name: test_pgp_id_seq; Type: SEQUENCE; Schema: public; Owner: sandino
--

CREATE SEQUENCE public.test_pgp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.test_pgp_id_seq OWNER TO sandino;

--
-- Name: test_pgp_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sandino
--

ALTER SEQUENCE public.test_pgp_id_seq OWNED BY public.test_pgp.id;


--
-- Name: test_rsa; Type: TABLE; Schema: public; Owner: sandino
--

CREATE TABLE public.test_rsa (
    id integer NOT NULL,
    val public.enigma(3)
);


ALTER TABLE public.test_rsa OWNER TO sandino;

--
-- Name: test_rsa_id_seq; Type: SEQUENCE; Schema: public; Owner: sandino
--

CREATE SEQUENCE public.test_rsa_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.test_rsa_id_seq OWNER TO sandino;

--
-- Name: test_rsa_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sandino
--

ALTER SEQUENCE public.test_rsa_id_seq OWNED BY public.test_rsa.id;


--
-- Name: test_both id; Type: DEFAULT; Schema: public; Owner: sandino
--

ALTER TABLE ONLY public.test_both ALTER COLUMN id SET DEFAULT nextval('public.test_both_id_seq'::regclass);


--
-- Name: test_epgp id; Type: DEFAULT; Schema: public; Owner: sandino
--

ALTER TABLE ONLY public.test_epgp ALTER COLUMN id SET DEFAULT nextval('public.test_epgp_id_seq'::regclass);


--
-- Name: test_ersa id; Type: DEFAULT; Schema: public; Owner: sandino
--

ALTER TABLE ONLY public.test_ersa ALTER COLUMN id SET DEFAULT nextval('public.test_ersa_id_seq'::regclass);


--
-- Name: test_pgp id; Type: DEFAULT; Schema: public; Owner: sandino
--

ALTER TABLE ONLY public.test_pgp ALTER COLUMN id SET DEFAULT nextval('public.test_pgp_id_seq'::regclass);


--
-- Name: test_rsa id; Type: DEFAULT; Schema: public; Owner: sandino
--

ALTER TABLE ONLY public.test_rsa ALTER COLUMN id SET DEFAULT nextval('public.test_rsa_id_seq'::regclass);


--
-- Data for Name: test_both; Type: TABLE DATA; Schema: public; Owner: sandino
--

COPY public.test_both (id, val1, val2) FROM stdin;
1	PgE_PGP100000002\nwYwDy31dohr4uGABA/9iLU8G7m1kJaet4yQiAu1Ew+pj6pzSU8jZ/eZimim6G2zV\nSSlT6bR/Uc6UIT9CpOWqhISg/3Tlk+nQRBtbo2VK/8eC+vO2NxSVIVkiCM5Ij+Ak\nz6P5AR94QrITggDgn24ztvxFdYivAImXOoazQcEAb+4arTRwpRE37ej66p3L+9JD\nAZjU5IvqF/vMVnjxO3XsL7fHPsBZrv1taLEiVN/g8yJNkAn5aWK5MzJvSqvDFQ4x\nOqd0LjgNiSdrG3VKrfS3RWECag==\n=IPIc\n	PgE_RSA100000003\nzK830KOmFaQ94/PEcfqCpssL6SIhF9xPI8jBqi/gRVyKH29UvTYGQK2QvVHLrSbX2inVJXltBoYOU1AO2ND1bhU8dzCtoUhstRPyzt8Gs2zCIfERHN6zAs6aOI2ao0b06rCBaAFF/xpd8YhDa9lsAkhhPqifPkJmzXBsXxvm6ss=
\.


--
-- Data for Name: test_epgp; Type: TABLE DATA; Schema: public; Owner: sandino
--

COPY public.test_epgp (id, val) FROM stdin;
1	PgE_PGP100000002\nwYwDy31dohr4uGABA/9O9PBrZLKAhkBObFqxbyN2jOthQoXmTmGpBvYP58cpbiLw\nslmEqkFSJ24j6Y6h1ioGx8ZpfsWy5UYlSbSdiVB0QGRtmH+ZBbOIrQN1zojseTT1\nA/BQknRO7vE+3OjCQSpSI/+95NKz3YiwraCaKSdDEaotkQd2j8G2/Mwrq9qqFtJP\nAX+peEuxH9iwyXGRqMs/icxiV+LAf7Dwn28XA9cGp+G8dAn7xraokqq1dpSeqgH7\nBg3XPhfa9SMXy7N8JyAGFZs6dLnlD+JxuUS7zpaAAQ==\n=fjF9\n
\.


--
-- Data for Name: test_ersa; Type: TABLE DATA; Schema: public; Owner: sandino
--

COPY public.test_ersa (id, val) FROM stdin;
1	PgE_RSA100000003\nwqiwNQRa3DSxRkRUUMntKw6INX+6+I3PxQoSkcvq6YgV5MYduoEZgmRGUqNyax6Fw\n8oyzLjCvyIVURLpDODXM3TK0XUTONB2v66y9aU/J4FKFHeFDPIGZumdXmReBXbTbs\nlQa4Pnuo5+usyy+LfOAyKDr6GveC5wpsrtEHtuXOg=
\.


--
-- Data for Name: test_pgp; Type: TABLE DATA; Schema: public; Owner: sandino
--

COPY public.test_pgp (id, val) FROM stdin;
1	PgE_PGP100000002\nwYwDy31dohr4uGABA/9iLU8G7m1kJaet4yQiAu1Ew+pj6pzSU8jZ/eZimim6G2zV\nSSlT6bR/Uc6UIT9CpOWqhISg/3Tlk+nQRBtbo2VK/8eC+vO2NxSVIVkiCM5Ij+Ak\nz6P5AR94QrITggDgn24ztvxFdYivAImXOoazQcEAb+4arTRwpRE37ej66p3L+9I/\nAZjU5IvqF/vMVnjxO3XsL7fHPsBVrv1taLEiU5bh5TUfT1b9EXcbX/8YIOlZBUQR\nApxdy5l+vDp2aaNEhF4d\n=SlT3\n
\.


--
-- Data for Name: test_rsa; Type: TABLE DATA; Schema: public; Owner: sandino
--

COPY public.test_rsa (id, val) FROM stdin;
1	PgE_RSA100000003\nPgQ2vZ3WH8KclgsbyCdKHEFJeHydAxpa0FFShomabqkdivTMtmV5TMW0Lf31JvdgOPc8m438qSqYk5L7hAynF4Lp2EH+mxHUp95l1x7RE6B8cPHMATM5Kdgn7Rld2Uh/JLXw0WYBX1SO3qXrseSFsLsMvXIJk4DuOC4LlS+15IU=
\.


--
-- Name: test_both_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sandino
--

SELECT pg_catalog.setval('public.test_both_id_seq', 1, true);


--
-- Name: test_epgp_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sandino
--

SELECT pg_catalog.setval('public.test_epgp_id_seq', 1, true);


--
-- Name: test_ersa_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sandino
--

SELECT pg_catalog.setval('public.test_ersa_id_seq', 1, true);


--
-- Name: test_pgp_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sandino
--

SELECT pg_catalog.setval('public.test_pgp_id_seq', 1, true);


--
-- Name: test_rsa_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sandino
--

SELECT pg_catalog.setval('public.test_rsa_id_seq', 1, true);


--
-- PostgreSQL database dump complete
--

\unrestrict IKADtaQJVk1VYEADMPxNc8lVXL16lAobuEkq6Y7jsCCiVjfM2UFILgiKJnh2hHM

