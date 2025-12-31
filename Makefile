# pg_enigma

# TODO: Obtain TEST_VERSIONS from Cargo.toml
TEST_VERSIONS := 13 14 15 16 17 18

required postgres_version:
ifndef POSTGRES_VERSION
	$(error Postgres version is needed, please define the POSTGRES_VERSION)
	$(error environment variable)
endif

.PHONY: test clean

run:
ifdef POSTGRES_VERSION
	cargo pgrx run pg${POSTGRES_VERSION}
else
	cargo pgrx run
endif

test:
ifdef POSTGRES_VERSION
	cargo pgrx test pg${POSTGRES_VERSION}
else
	cargo pgrx test
endif

test_all:
	for V in $(TEST_VERSIONS) ; do \
		echo "Testing for Postgres version: $$V" ; \
		POSTGRES_VERSION=$$V make test; \
	done

build: required_postgres_version
	export PGRX_HOME=./.pgrx
	export PGRX_PG_CONFIG_PATH=/usr/bin/pg_config
	cargo pgrx init --pg${POSTGRES_VERSION} ${PGRX_PG_CONFIG_PATH} --no-run
	cargo pgrx package --no-default-features --features=pg${POSTGRES_VERSION} --verbose

install:
	cargo pgrx install

clean:
	cargo clean
