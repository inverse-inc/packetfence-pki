%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')
%define serverroot /usr/local/packetfence-pki
Name: packetfence-pki
Version: 1.1.3
Release: 1%{?dist}
Summary: packetfence-pki

Group:	System/Servers
License: GPL
Buildarch: noarch
URL: https://github.com/inverse-inc/packetfence-pki
Source0: packetfence-pki-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires:	python
Requires: httpd, mod_wsgi, mod_ssl, python, python-django-bootstrap3, django-countries >= 5.0, python-django-rest-framework, python-django >= 1.8, pyOpenSSL >= 17.2, python-ldap, python-pyasn1 >= 0.1.7 , python-pyasn1-modules >= 0.1.7, python-six, python2-cryptography >= 2.0.2, python2-django-formtools >= 1.0, python-django-tagging >= 0.3.6, python2-asn1crypto, python-idna, python-ipaddress

%description
Small PKI to integrate with PacketFence for certificates generation when using EAP-TLS

%prep
%setup -q

%build
rm -rf $RPM_BUILD_ROOT


%install
make PREFIX=$RPM_BUILD_ROOT%{serverroot} PREFIXLIB=$RPM_BUILD_ROOT%{serverroot} UID='-o nobody' GID='-g nobody' install
%{__install} -D -m0644 conf/packetfence-pki.service $RPM_BUILD_ROOT/usr/lib/systemd/system/packetfence-pki.service

%clean
rm -rf %{buildroot}

%pre

if ! /usr/bin/id pf &>/dev/null; then
        /usr/sbin/useradd -r -d "/usr/local/packetfence-pki" -s /bin/sh -c "PacketFence" -M pf || \
                echo Unexpected error adding user "pf" && exit
fi

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
cd %{serverroot} && python manage.py makemigrations && python manage.py migrate
fi
chown -R pf.pf %{serverroot}
chown pf.pf %{serverroot}/conf/httpd.conf
chmod 600 %{serverroot}/conf/httpd.conf

echo "Disabling SELinux..."
setenforce 0
sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config

/bin/systemctl enable packetfence-pki
/bin/systemctl start packetfence-pki

set +e
/usr/bin/firewall-cmd --zone=public --add-port=9292/tcp
/usr/bin/firewall-cmd --zone=public --add-port=9393/tcp
set -e

%preun
if [ $1 -eq 0 ] ; then
        /sbin/service packetfence-pki stop &>/dev/null || :
        /sbin/chkconfig --del packetfence-pki
fi

%postun
if [ $1 -eq 0 ]; then
        if /usr/bin/id pf &>/dev/null; then
               set +e
               /usr/sbin/userdel pf || %logmsg "User \"pf\" could not be deleted."
               set -e
        fi
fi

%files
%defattr(-,apache,apache,-)
%config(noreplace) %{serverroot}/conf/*
%{serverroot}/inverse/*
%{serverroot}/pki/*
%{serverroot}/manage.py
%dir %{serverroot}/logs
%dir %{serverroot}/ca
%defattr(-,root,root)
%attr(0644, root, root) /usr/lib/systemd/system/packetfence-*.service

%changelog
