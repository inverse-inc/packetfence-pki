%define serverroot /usr/local/packetfence-pki
Name: packetfence-pki
Version: 1.00
Release: 1%{?dist}
Summary: packetfence-pki

Group:	System/Servers
License: GPL
URL: https://github.com/inverse-inc/packetfence-pki
Source0: packetfence-pki-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires:	python
Requires: python

%description
Small PKI to integrate with PacketFence for certificates generation when using EAP-TLS

%prep
%setup -q

%build
rm -rf $RPM_BUILD_ROOT


%install
#cd %{name}-%{version}
make PREFIX=$RPM_BUILD_ROOT%{serverroot} PREFIXLIB=$RPM_BUILD_ROOT%{serverroot} UID='-o apache' GID='-g apache' install


%clean
rm -rf %{buildroot}


%files
%defattr(-,apache,apache,-)
%config(noreplace) %{serverroot}//conf/*
%{serverroot}/inverse/*
%{serverroot}/pki/*
%{serverroot}/manage.py
%exclude %{serverroot}/manage.pyc
%exclude %{serverroot}/manage.pyo

%changelog
