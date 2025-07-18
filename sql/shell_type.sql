-- Public keys table stores public keys permanently
-- Public keys are stored as armored text
CREATE TABLE IF NOT EXISTS _enigma_public_keys (
	id INT PRIMARY KEY,
	public_key TEXT 
);
-- enigma shell_type
CREATE TYPE enigma;
