CREATE TYPE enigma (
	INPUT  = enigma_input_with_typmod,
	OUTPUT = enigma_output,
	RECEIVE = enigma_receive_with_typmod,
	SEND = enigma_send,
	TYPMOD_IN = enigma_type_modifier_input
);

