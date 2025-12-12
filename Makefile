# pg_enigma

postgres_version:
ifndef POSTGRES_VERSION
	$(info Postgres version is not defined.)
	$(info Trying to guess version from installed pg_config...)
	POSTGRES_VERSION := $(shell /usr/bin/pg_config --version | cut -d ' ' -f 2 | cut -d '.' -f 1 )
ifndef POSTGRES_VERSION
	$(error POSTGRES_VERSION is needed for build)
endif
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

postgres_version:

build: postgres_version
	export PGRX_HOME=./.pgrx
	cargo pgrx init --pg${POSTGRES_VERSION} /usr/bin/pg_config --no-run
	export PGRX_PG_CONFIG_PATH=/usr/bin/pg_config
	cargo pgrx package --no-default-features --features=pg${POSTGRES_VERSION} --verbose

install:
	cargo pgrx install

clean:
	cargo clean
