-- Public keys table stores public keys permanently
-- Public keys are stored as armored text
CREATE TABLE IF NOT EXISTS _enigma_public_keys (
	id INT PRIMARY KEY,
	public_key TEXT 
);
-- Enigma shell_type
CREATE TYPE Enigma;
-- Epgp shell_type
CREATE TYPE Epgp;
