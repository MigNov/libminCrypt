Name:		libmincrypt
Version:	0.0.5
Release:	1%{?dist}%{?extra_release}
Summary:	Library form of minCrypt crypto-algorithm implementation
Source:		http://www.migsoft.net/projects/mincrypt/libmincrypt-%{version}.tar.xz

Group:		Development/Libraries
License:	LGPLv2+
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root

%description
Library for minCrypt minimal encryption/decryption system

%prep
%setup -q -n libmincrypt-%{version}

%build
%configure
make %{?_smp_mflags}

%install
mkdir -p %{buildroot}/%{_libdir}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE README
%{_bindir}/mincrypt
%{_libdir}/libmincrypt.a
%{_libdir}/libmincrypt.la
%{_libdir}/libmincrypt.so
%{_libdir}/libmincrypt.so.0
%{_libdir}/libmincrypt.so.0.0.0
%{_includedir}/mincrypt.h

%changelog
* Thu Mar 15 2012 Michal Novotny <mignov@gmail.com> - 0.0.5:
- Fix asymmetric key generation algorithm to generate random initialization vectors

* Thu Dec 20 2011 Michal Novotny <mignov@gmail.com> - 0.0.4:
- Split minCrypt project into minCrypt binary and libminCrypt library
