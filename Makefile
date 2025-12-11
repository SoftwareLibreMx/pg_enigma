# pg_enigma

ifndef POSTGRES_VERSION
        $(error Postgres version is needed, please define the POSTGRES_VERSION)
        $(error environment variable)
endif

.PHONY: test clean

run:
	cargo pgrx run

test:
	cargo pgrx test

build:
	export PGRX_HOME=./.pgrx
	cargo pgrx init --pg${POSTGRES_VERSION} /usr/bin/pg_config --no-run
	export PGRX_PG_CONFIG_PATH=/usr/bin/pg_config
	cargo pgrx package --no-default-features --features=pg${POSTGRES_VERSION} --verbose

install:
	cargo pgrx install

clean:
	cargo clean
