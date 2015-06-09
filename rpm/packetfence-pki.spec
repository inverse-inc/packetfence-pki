%define serverroot /usr/local/packetfence-pki
Name: packetfence-pki
Version: %{ver}
Release: 1%{?dist}
Summary: packetfence-pki

Group:	System/Servers
License: GPL
Buildarch: noarch
URL: https://github.com/inverse-inc/packetfence-pki
Source0: packetfence-pki-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires:	python
Requires: python, python-django-bootstrap3, python-django-rest-framework, python-django, pyOpenSSL, python-ldap, python-pyasn1 >= 0.1.7 , python-pyasn1-modules >= 0.1.7

%description
Small PKI to integrate with PacketFence for certificates generation when using EAP-TLS

%prep
%setup -q

%build
rm -rf $RPM_BUILD_ROOT


%install
make PREFIX=$RPM_BUILD_ROOT%{serverroot} PREFIXLIB=$RPM_BUILD_ROOT%{serverroot} UID='-o apache' GID='-g apache' install
install -d -m0700 $RPM_BUILD_ROOT/etc/init.d
install -m0755 rpm/%{name} $RPM_BUILD_ROOT/etc/init.d/%{name}

%clean
rm -rf %{buildroot}

%post
if [ -f %{serverroot}/conf/server.crt ] ; then
        echo "certificate exist do nothing"
else
        openssl req -x509 -new -nodes -days 365 -batch\
        -out %{serverroot}/conf/server.crt\
        -keyout %{serverroot}/conf/server.key\
        -nodes -config %{serverroot}/conf/openssl.cnf
fi
if [ -f %{serverroot}/db.sqlite3 ] ; then
        echo "Database is there do nothing"
else
cd %{serverroot} && python manage.py syncdb --noinput
fi
chown -R pf.pf %{serverroot}
chown pf.pf %{serverroot}/conf/httpd.conf
chmod 600 %{serverroot}/conf/httpd.conf


%files
%defattr(-,apache,apache,-)
%config(noreplace) %{serverroot}/conf/*
%{serverroot}/inverse/*
%{serverroot}/pki/*
%{serverroot}/manage.py
%{serverroot}/initial_data.json
%exclude %{serverroot}/manage.pyc
%exclude %{serverroot}/manage.pyo
%defattr(-,root,root)
/etc/init.d/%{name}

%changelog
