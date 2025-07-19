%define pg_version %(pg_config --version  | cut -d ' ' -f 2 | cut -d '.' -f 1)
%global buildpath %{_builddir}/pg_enigma/target/release/%{name}-pg%{pg_version}
%global pg_libdir %{_libdir}/pgsql/
%global pg_sharedir %{_datadir}/pgsql/extension/
%global enigma_mirror https://github.com/SoftwareLibreMx/pg_enigma/archive/refs/tags/

Name:           pg_enigma
Version:        0.3.0
Release:        1.pg%{pg_version}%{?dist}
Summary:        Column level encryption for PostgreSQL

License:        PostgreSQL
URL:            https://git.softwarelibre.mx/SoftwareLibreMx/%{name}
# Use github mirror for Source0
Source0:        %{enigma_mirror}%{name}-%{version}.tar.gz

BuildRequires:  cargo
# TODO: BuildRequires: cargo-pgrx
# in the meanwhile, copying ~/.cargo/bin/cargo-pgrx to /usr/local/bin/cargo-pgrx will do the work
BuildRequires:  clang
BuildRequires:  postgresql-server-devel
BuildRequires:  rustfmt

Requires:       postgresql-server = %{pg_version}

%description
A PostgreSQL extension that adds custom data types to allow column-level encryption. pg_enigma
enables users, DBAs and developers to protect sensitive data and allow separation of concerns by
using public key cryptography standards such as PGP and RSA.

%prep
%setup -q -n %{name}

#check
## Run the test suite provided by pgrx.
## This requires a running PostgreSQL instance, which pgrx manages  
#export PGRX_HOME=./.pgrx
#export PGRX_PG_CONFIG_PATH=/usr/bin/pg_config
### This test requires write permision on /usr/share/pgsql/extension
#cargo pgrx test --no-default-features --features=pg16 --verbose
### Error:
###    0: failed to create destination directory /usr/share/pgsql/extension
###    1: Permission denied (os error 13)

# TODO: Test script for using with postgres --single
# postgres --single -c dynamic_library_path='%{pg_libdir}:$$libdir' -f enigma_test.sql pg_enigma
# BuildRequires:  postgresql-server

%build
export PGRX_HOME=./.pgrx
cargo pgrx init --pg%{pg_version} /usr/bin/pg_config --no-run
export PGRX_PG_CONFIG_PATH=/usr/bin/pg_config
cargo pgrx package --no-default-features --features=pg%{pg_version} --verbose

%install
install -d %{buildroot}%{pg_libdir}
install -d %{buildroot}%{pg_sharedir}

install -m 755 %{buildpath}%{pg_libdir}%{name}.so %{buildroot}%{pg_libdir}
install -m 755 %{buildpath}%{pg_sharedir}%{name}.control %{buildroot}%{pg_sharedir}
install -m 755 %{buildpath}%{pg_sharedir}%{name}--%{version}.sql %{buildroot}%{pg_sharedir}

%files
%defattr(-,root,root,-)
%doc README.md
%license LICENSE
%{pg_libdir}%{name}.so
%{pg_sharedir}%{name}.control
%{pg_sharedir}%{name}*.sql

%changelog
* Fri Jul 18 2025 Sandino Araico Sánchez <sandino@sandino.net> - 0.2.1-1
- Use github mirror for Source0

* Fri Jul 11 2025 Sandino Araico Sánchez <sandino@sandino.net> - 0.2.0-1
- Fixed pgrx config for pg16
- Extra parameters for cargo pgrx package
- Simplified install paths

* Wed Jul 09 2025 Iván Chavero <ichavero@chavero.com.mx> - 0.2.0-1
- Updated upstream package format
- Bump version to 0.2.0

* Mon Jul 07 2025 Iván Chavero <ichavero@chavero.com.mx> - 0.1.0-1
- Initial RPM release.

