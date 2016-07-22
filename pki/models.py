from django.template import Context, Template
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User
from django.db import models
from django_countries.fields import CountryField
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459, pem

from email import Encoders
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.Utils import COMMASPACE, formatdate


from OpenSSL import crypto
import datetime
import operator
import smtplib
import hashlib
import string
import ldap
import os


class CA(models.Model):
    cn = models.CharField(max_length=20,unique=1,help_text="Common Name")
    mail = models.EmailField(help_text="Email address of the contact for your organisation")
    organisation = models.CharField(max_length=40,help_text="Organisation")
    country = CountryField(help_text="Country")
    state = models.CharField(max_length=40,help_text="State or Province")
    locality = models.CharField(max_length=40,help_text="Locality")
    key_type = models.IntegerField(choices=((crypto.TYPE_RSA, 'RSA'), (crypto.TYPE_DSA, 'DSA')))
    key_size = models.IntegerField(choices=((512, '512'), (1024, '1024'), (2048, '2048')))
    digest = models.CharField(max_length=10, choices=(('md5', 'md5'),('sha1', 'sha1')))
    key_usage = models.CharField(max_length=50,blank=1,help_text="Optional. One or many of: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly")
    extended_key_usage = models.CharField(max_length=50,blank=1,help_text="Optional. One or many of: serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, msCodeInd, msCodeCom, msCTLSign, msSGC, msEFS, nsSGC")
    days = models.IntegerField(max_length=4,help_text="Number of day the CA will be valid")
    ca_key = models.TextField(blank=1,null=1,editable=False)
    ca_cert = models.TextField(blank=1,null=1,editable=False)
    issuerKeyHashmd5 = models.TextField(blank=1,null=1,max_length=33,editable=False)
    issuerKeyHashsha1 = models.TextField(blank=1,null=1,max_length=41,editable=False)
    issuerKeyHashsha256 = models.TextField(blank=1,null=1,max_length=65,editable=False)
    issuerKeyHashsha512 = models.TextField(blank=1,null=1,max_length=129,editable=False)
    def sign(self):
        k = crypto.PKey()
        k.generate_key(self.key_type, self.key_size)
        cert = crypto.X509()
        subj = cert.get_subject()
        setattr(subj, 'CN', self.cn)
        setattr(subj, 'emailAddress', self.mail)
        setattr(subj, 'ST', self.state)
        setattr(subj, 'O', self.organisation)
        setattr(subj, 'C', str(self.country))
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.days * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        if self.key_usage:
            cert.add_extensions([crypto.X509Extension("keyUsage", True,self.key_usage)])
        if self.extended_key_usage:
            cert.add_extensions([crypto.X509Extension("extendedKeyUsage", True,self.extended_key_usage)])
        cert.add_extensions([crypto.X509Extension("basicConstraints", True, "CA:TRUE")])
        cert.sign(k, str(self.digest))
        self.ca_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
        self.ca_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        certType = rfc2459.Certificate()
        substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        certif, rest = decoder.decode(substrate, asn1Spec=certType)
        issuerTbsCertificate = certif.getComponentByName('tbsCertificate')
        issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName('subjectPublicKey')
        self.issuerKeyHashmd5 = hashlib.md5(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
        self.issuerKeyHashsha1 = hashlib.sha1(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
        self.issuerKeyHashsha256 = hashlib.sha256(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
        self.issuerKeyHashsha512 = hashlib.sha512(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
        self.save_ca()
    def get_absolute_url(self):
        return reverse('ca_update', kwargs={'pk': self.pk})
    def __str__(self):
        return self.cn
    def pkcs12(self, passphrase):
        p12 = crypto.PKCS12()
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.ca_key)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.ca_cert)
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        return crypto.dump_pkcs12(p12,passphrase, "")
    def save_ca(self):
        my_ca_file = open(os.path.join('/usr/local/packetfence-pki/ca/', self.cn+'.pem'), 'w')
        my_ca_file.write(self.ca_cert)

class Attrib(models.Model):
    ATTRIBUT_TYPE = (
        ('user','User Schema'),
        ('group','Group Schema'),
        )
    attribut = models.CharField(max_length=20)
    value = models.CharField(max_length=20, blank=1, null=1)
    description = models.CharField(max_length=40, blank=1, null=1)
    type = models.CharField(max_length=10,choices=ATTRIBUT_TYPE, default="user")

    def __unicode__(self):
        return self.attribut + " (" + self.value + ")"

    def get_absolute_url(self):
        return reverse('attribut_update', kwargs={'pk': self.pk})

class SCHEMA(models.Model):
    name = models.CharField(max_length=20,unique=1)
    attribut = models.ManyToManyField(Attrib)

    def __unicode__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('schema_update', kwargs={'pk': self.pk})

class LDAP(models.Model):
    LDAP_ENC_SCHEMES = (
        ('none','none (usual port: 389)'),
        ('ldaps','ldaps (usual port: 636)'),
        ('start-tls','start-tls (usual port: 389)'),
        )
    LDAP_SCOPE = (
        (ldap.SCOPE_SUBTREE,'subtree (all levels under suffix)'),
        (ldap.SCOPE_ONELEVEL,'one (one level under suffix)'),
        (ldap.SCOPE_BASE,'base (the suffix entry only)'),
        )
    LDAP_VERSIONS = (
        (2,'LDAP v2'),
        (3,'LDAP v3'),
        )
    name = models.CharField(max_length=20)
    host = models.CharField(max_length=20)
    port = models.IntegerField()
    protocol = models.IntegerField(choices=LDAP_VERSIONS)
    scheme = models.CharField(max_length=10,choices=LDAP_ENC_SCHEMES, default="none")
    cacert_path = models.CharField(max_length=20, blank=1, null=1)
    schema = models.ForeignKey('SCHEMA',null=True)
    base_dn = models.CharField(max_length=50)
    dn = models.CharField(max_length=50)
    password = models.CharField(max_length=20)
    user_ou = models.CharField(max_length=100)
    user_attr = models.CharField(max_length=20)
    user_scope = models.IntegerField(choices=LDAP_SCOPE)
    user_filter = models.CharField(max_length=100, default="(|(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=person))")
    group_ou = models.CharField(max_length=100)
    group_attr = models.CharField(max_length=50)
    group_scope = models.IntegerField(choices=LDAP_SCOPE)
    group_filter = models.CharField(max_length=100, default="(|(objectclass=posixGroup)(objectclass=group)(objectclass=groupofuniquenames))")
    group_member = models.CharField(max_length=20)
    are_members_dn = models.BooleanField(default=None)

    def search(self, base_dn, scope, filter, attr):
        ko = []
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            result_id = l.search(base_dn, scope, filter.encode('utf-8'), attr)
            while 1:
                result_type, result_data = l.result(result_id, 0)
                if not result_data:
                    break
                if result_type == ldap.RES_SEARCH_ENTRY:
                    ko.append(result_data)
        except ldap.LDAPError, error_message:
            print error_message
        return sorted(ko, key=operator.itemgetter(0))

    def group_ok(self, dn):
        group_filter = "(&"+self.group_filter+"(member="+dn+"))"
        ret = self.search(self.base_dn, self.group_scope, group_filter, [ str(self.group_attr) ])
        return ret

    def all_groups(self):
         ret = self.search(self.base_dn, self.group_scope, self.group_filter, [ str(self.group_attr) ])
         return ret

    def group_ko(self, group_ok):
        group_filter = "(&"+self.group_filter
        for group in group_ok:
            name = group[0][1][self.group_attr][0]
            group_filter += "(!("+self.group_attr+"="+name.decode('utf-8')+"))"
        group_filter += ")"
        ret = self.search(self.base_dn, self.group_scope, group_filter, [ str(self.group_attr) ])
        return ret

    def modify(self, dn, attrs):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.modify_s(dn.encode('latin-1'), attrs)
        except ldap.LDAPError, error_message:
            raise error_message

    def add(self, dn, attrs):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.add_s(dn.encode('latin-1'), attrs)
            print "ADD %s" % dn
            print attrs
        except ldap.LDAPError, error_message:
            print error_message

    def member(self, mod_type, group_cn, user_dn):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            dn = self.group_attr + "=" + group_cn + ",ou=" + self.group_ou + "," + self.base_dn
            l.modify_s(dn.encode('utf-8'), [(mod_type, "member", user_dn.encode('utf-8'))])
        except ldap.LDAPError, error_message:
            print error_message

    def all_users(self):
         ret = self.search(self.base_dn, self.user_scope, self.user_filter, [ str(self.user_attr) ])
         return ret

    def delete_user(self, uid):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.delete_s("uid="+uid+",ou="+self.user_ou+","+self.base_dn)
        except ldap.LDAPError, error_message:
            print error_message

    def delete_group(self, cn):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.delete_s("cn="+cn+",ou="+self.group_ou+","+self.base_dn)
        except ldap.LDAPError, error_message:
            print error_message

    def __unicode__(self):
        return self.host

    def get_absolute_url(self):
        return reverse('ldap_update', kwargs={'pk': self.pk})

class CertProfile(models.Model):
    name = models.CharField(max_length=20,unique=1,help_text="Profile Name")
    ca = models.ForeignKey(CA)
    validity = models.IntegerField(help_text="Number of day the certificate will be valid")
    key_type = models.IntegerField(choices=((crypto.TYPE_RSA, 'RSA'), (crypto.TYPE_DSA, 'DSA')))
    key_size = models.IntegerField(choices=((512, '512'), (1024, '1024'),(2048, '2048')))
    digest = models.CharField(max_length=10, choices=(('md5', 'md5'),('sha1', 'sha1'),('sha256', 'sha256')))
    key_usage = models.CharField(max_length=50,blank=1,help_text="Optional. One or many of: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly")
    extended_key_usage = models.CharField(max_length=50,blank=1,help_text="Mandatory. Should be serverAuth for a Server Profile, clientAuth for a User Profile")
    p12_smtp_server = models.CharField(max_length=30,help_text="IP or FQDN of the smtp server to relay the email containing the certificate.")
    p12_mail_password = models.BooleanField(default=None,help_text="Send the password of the pkcs12 file?")
    p12_mail_subject = models.CharField(max_length=30,blank=1,help_text="Email subject")
    p12_mail_from = models.CharField(max_length=50,blank=1,help_text="Sender email address")
    p12_mail_header = models.TextField(blank=1,help_text="Email header")
    p12_mail_footer = models.TextField(blank=1,help_text="Email footer")
    def get_absolute_url(self):
        return reverse('profile_update', kwargs={'pk': self.pk})
    def __str__(self):
        return self.name

class Cert(models.Model):
    REVOKE_REASON = (
        ('unspecified', 'reason is unknown'),
        ('keyCompromise', 'private key has been compromised'),
        ('cACompromise', 'certificate authority has been compromised'),
        ('affiliationChanged', 'affiliation has been changed'),
        ('superseded', 'certificate has been superseded'),
        ('cessationOfOperation' ,'cessation of operation'),
        ('certificateHold', 'certificate is on hold'),
        ('removeFromCRL', 'certificate was previously in a CRL, but is now valid'),
        ('privilegeWithdrawn', 'privilege has been withdrawn'),
        ('aACompromise', 'attribute authority has been compromised'),
        )
    cn = models.CharField(max_length=20,unique=1, help_text="Username for this certificate")
    mail = models.EmailField(help_text="Email address of the user. The email with the certificate will be sent to this address.")
    x509 = models.TextField(blank=1,null=1)
    st = models.CharField(max_length=40, help_text="State or Province")
    organisation = models.CharField(max_length=40)
    country = CountryField(help_text="Country")
    pkey = models.TextField(blank=1,null=1)
    profile = models.ForeignKey(CertProfile, help_text="Which Certificate Profile to use to create this certificate")
    valid_until = models.DateTimeField(auto_now_add=1,blank=1,null=1, help_text="Expiration date of the certificate")
    date = models.DateTimeField(auto_now_add=1,blank=1,null=1)
    revoked = models.DateTimeField(blank=1,null=1, help_text="Date of the certificate's revocation")
    CRLReason = models.CharField(max_length=20,choices=REVOKE_REASON, blank=1,null=1, help_text="Certificate revocation reason")
    userIssuerHashmd5 = models.TextField(blank=1,null=1,max_length=33,editable=False)
    userIssuerHashsha1 = models.TextField(blank=1,null=1,max_length=41,editable=False)
    userIssuerHashsha256 = models.TextField(blank=1,null=1,max_length=65,editable=False)
    userIssuerHashsha512 = models.TextField(blank=1,null=1,max_length=129,editable=False)
    def valid_until_str(self):
        return self.valid_until.strftime("%d/%m/%Y")
    def sign(self):
        req = crypto.X509Req()
        subj = req.get_subject()
        setattr(subj, 'CN', self.cn)
        setattr(subj, 'emailAddress', self.mail)
        setattr(subj, 'ST', self.st)
        setattr(subj, 'O', self.organisation)
        setattr(subj, 'C', str(self.country))
        pkey = crypto.PKey()
        pkey.generate_key(self.profile.key_type, self.profile.key_size)
        req.set_pubkey(pkey)
        req.sign(pkey, str(self.profile.digest))
        self.pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        x509 = crypto.X509()
        x509.set_subject(req.get_subject())
        x509.set_pubkey(req.get_pubkey())
        cacert = crypto.load_certificate(crypto.FILETYPE_PEM, self.profile.ca.ca_cert)
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, self.profile.ca.ca_key)
        x509.set_issuer(cacert.get_subject())
        x509.set_serial_number(self.id)
        x509.gmtime_adj_notBefore(-3600)
        self.valid_until = self.date + datetime.timedelta(days=self.profile.validity)
        delta = self.valid_until.date() - self.date.date();
        x509.gmtime_adj_notAfter(delta.days * 60 * 60 * 24)
        if self.profile.key_usage:
            x509.add_extensions([crypto.X509Extension("keyUsage", True,str(self.profile.key_usage))])
        if self.profile.extended_key_usage:
            x509.add_extensions([crypto.X509Extension("extendedKeyUsage", True, str(self.profile.extended_key_usage))])
        x509.sign(cakey, str(self.profile.digest))
        self.x509 = crypto.dump_certificate(crypto.FILETYPE_PEM, x509)
        certType = rfc2459.Certificate()
        substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)
        cert, rest = decoder.decode(substrate, asn1Spec=certType)
        userTbsCertificate = cert.getComponentByName('tbsCertificate')
        userIssuer = userTbsCertificate.getComponentByName('issuer')
        self.userIssuerHashmd5 = hashlib.md5(
            encoder.encode(userIssuer)
            ).hexdigest()
        self.userIssuerHashsha1 = hashlib.sha1(
            encoder.encode(userIssuer)
            ).hexdigest()
        self.userIssuerHashsha256 = hashlib.sha256(
            encoder.encode(userIssuer)
            ).hexdigest()
        self.userIssuerHashsha512 = hashlib.sha512(
            encoder.encode(userIssuer)
            ).hexdigest()
    def get_absolute_url(self):
        return "/pki/cert/"
    def pkcs12(self, passphrase):
        p12 = crypto.PKCS12()
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.pkey)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.x509 + "\n" + self.profile.ca.ca_cert)
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        return p12.export(passphrase)
    def pemf(self, passphrase):
        pem = crypto.X509()
        blump = self.pkey
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.pkey)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.x509 + "\n" + self.profile.ca.ca_cert)
        pem.set_privatekey(key)
        pem.set_certificate(cert)
    def send_password(self, passphrase):
        msg = MIMEMultipart()
        msg['From'] = self.profile.p12_mail_from
        msg['To'] = self.mail
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = self.profile.p12_mail_subject
        Text = Template("Dear {{ cn }} {{ header }} {{ password }} {{ footer }}")
        msg.attach(MIMEText(Text.render(Context({'cn': self.cn,'header': self.profile.p12_mail_header, 'footer': self.profile.p12_mail_footer, 'password': passphrase})), 'plain', 'utf-8'))
# 	pdf = MIMEBase('application', "octet-stream")
#       pdf.set_payload(open("/help.pdf").read())
#	Encoders.encode_base64(pdf)
#	pdf.add_header('Content-Disposition', 'attachment; filename="aide.pdf"')
#	msg.attach(pdf)
        smtp = smtplib.SMTP(self.profile.p12_smtp_server)
        smtp.sendmail(self.profile.p12_mail_from, self.mail, msg.as_string())
        smtp.close()
    def send_cert(self, passphrase):
        msg = MIMEMultipart()
        msg['From'] = self.profile.p12_mail_from
        msg['To'] = self.mail
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = self.profile.p12_mail_subject
        msg.attach(MIMEText(self.profile.p12_mail_header + ' ' + passphrase + "\n" + self.profile.p12_mail_footer, 'plain', 'utf-8'))
        part = MIMEBase('application', "octet-stream")
        part.set_payload(self.pkcs12(passphrase))
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s.p12"' % string.replace(self.cn, ' ', '_'))
        msg.attach(part)
# 	pdf = MIMEBase('application', "octet-stream")
#       pdf.set_payload(open("/help.pdf").read())
#	Encoders.encode_base64(pdf)
#	pdf.add_header('Content-Disposition', 'attachment; filename="aide.pdf"')
#	msg.attach(pdf)
        smtp = smtplib.SMTP(self.profile.p12_smtp_server)
        smtp.sendmail(self.profile.p12_mail_from, self.mail, msg.as_string())
        smtp.close()
    class Meta:
        db_table = 'cert'

class CertRevoked(models.Model):
    cn = models.CharField(max_length=20)
    mail = models.EmailField()
    x509 = models.TextField(blank=1,null=1)
    st = models.CharField(max_length=40)
    organisation = models.CharField(max_length=40)
    country = models.CharField(max_length=2, default='CA')
    pkey = models.TextField(blank=1,null=1)
    profile = models.ForeignKey(CertProfile)
    valid_until = models.DateTimeField(blank=1,null=1)
    date = models.DateTimeField(blank=1,null=1)
    revoked = models.DateTimeField(blank=1,null=1)
    CRLReason = models.CharField(max_length=20, blank=1,null=1)
    userIssuerHashmd5 = models.TextField(blank=1,null=1,max_length=33,editable=False)
    userIssuerHashsha1 = models.TextField(blank=1,null=1,max_length=41,editable=False)
    userIssuerHashsha256 = models.TextField(blank=1,null=1,max_length=65,editable=False)
    userIssuerHashsha512 = models.TextField(blank=1,null=1,max_length=129,editable=False)
    serial =  models.IntegerField(blank=1,null=1,max_length=6,editable=False)

class ValueOnlyBitStringEncoder(encoder.encoder.BitStringEncoder):
    # These methods just do not encode tag and length fields of TLV
    def encodeTag(self, *args): return ''
    def encodeLength(self, *args): return ''
    def encodeValue(*args):
        substrate, isConstructed = encoder.encoder.BitStringEncoder.encodeValue(*args)
        # OCSP-specific hack follows: cut off the "unused bit count"
        # encoded bit-string value.
        return substrate[1:], isConstructed

    def __call__(self, bitStringValue):
        return self.encode(None, bitStringValue, defMode=1, maxChunkSize=0)

valueOnlyBitStringEncoder = ValueOnlyBitStringEncoder()

class rest(models.Model):
    name = models.CharField(max_length=20,unique=1,help_text="REST Profile name")
    profile = models.ForeignKey(CertProfile, help_text="Certificate profile to associate with this API")
    allowed_users = models.ManyToManyField(User, help_text="User allowed to use this API from PacketFence")

    def get_absolute_url(self):
        return reverse('rest_update', kwargs={'pk': self.pk})
