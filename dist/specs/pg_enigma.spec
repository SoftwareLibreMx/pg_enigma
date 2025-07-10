%global base_name pg_enigma
%global pgmajorversion 16
%global pginstdir /usr
%global pg_libdir %{pginstdir}/lib64/pgsql
%global pg_sharedir %{pginstdir}/share/pgsql
%global buildpath %{_builddir}/pg_enigma/target/release/%{name}
%define debug_package %{nil}

Name:           %{base_name}-pg%{pgmajorversion}
Version:        0.1.0
Release:        1%{?dist}
Summary:        Column level encryption for PostgreSQL

License:        PostgreSQL
URL:            https://git.softwarelibre.mx/SoftwareLibreMx/%{base_name}
Source0:        %{url}/archive/v%{version}.tar.gz


BuildRequires:  postgresql-server-devel
BuildRequires:  postgresql-private-devel
BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  clang
BuildRequires:  make

Requires:       postgresql-server

%description
A PostgreSQL extension that adds custom data types to allow column-level encryption. pg_enigma
enables users, DBAs and developers to protect sensitive data and allow separation of concerns by
using public key cryptography standards such as PGP and RSA.

%prep
%setup -q -n %{base_name}

%check
# Run the test suite provided by pgrx.
# This requires a running PostgreSQL instance, which pgrx manages.
export PATH=%{pginstdir}/bin:$PATH
cargo pgrx test

%build
# pgrx requires pg_config to be in the PATH.
export PATH=%{pginstdir}/bin:$PATH
cargo pgrx package

%install
rm -rf %{buildroot}
install -d %{buildroot}/%{pg_libdir}
install -d %{buildroot}/%{pg_sharedir}/extension

install -m 755 %{buildpath}%{pg_libdir}/%{base_name}.so %{buildroot}/%{pg_libdir}/%{base_name}.so
install -m 755 %{buildpath}%{pg_sharedir}/extension/%{base_name}.control %{buildroot}/%{pg_sharedir}/extension/%{base_name}.control
install -m 755 %{buildpath}%{pg_sharedir}/extension/%{base_name}--%{version}.sql %{buildroot}/%{pg_sharedir}/extension/%{base_name}--%{version}.sql

%files
%defattr(-,root,root,-)
%doc README.md
%license LICENSE
%{pg_libdir}/%{base_name}.so
%{pg_sharedir}/extension/%{base_name}.control
%{pg_sharedir}/extension/%{base_name}*.sql

%changelog
* Mon Jul 07 2025 Iván Chavero <ichavero@chavero.com.mx> - 0.1.0-1
- Initial RPM release.

