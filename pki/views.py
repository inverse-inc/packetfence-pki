from django.contrib.auth.decorators import login_required, permission_required
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.contrib.formtools.wizard.views import SessionWizardView
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse_lazy
from django.shortcuts import render_to_response
from django.core.context_processors import csrf
from django.template import RequestContext
from django.shortcuts import render
from django.views import generic
from django.http import Http404

from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT
from OpenSSL import *

from pyasn1_modules import rfc2560, pem, rfc2459, rfc2437
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type import univ, useful

from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status

from pki.serializers import *
from pki.models import *
from pki.forms import *
from pki.utils import *

import datetime
import hashlib
import string
import random
import array
import json
import time
import logging

logger = logging.getLogger(__name__)

def logon(request):
    if request.user.is_authenticated():
        return HttpResponseRedirect("/pki/")
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active and user.is_staff:
                login(request, user)
                try:
                    ca = CA.objects.get()
                    #for AC in ca:
                    #    test = AC.id
                    return HttpResponseRedirect("/pki/")
                except CA.DoesNotExist:
                    return HttpResponseRedirect("/pki/init_wizard/")
    return render_to_response('logon.html',context_instance=RequestContext(request))

def disconnect(request):  
    logout(request)
    return HttpResponseRedirect("/logon/")


class AjaxableResponseMixin(object):
    """
    Mixin to add AJAX support to a form.
    Must be used with an object-based FormView (e.g. CreateView)
    """
    def render_to_json_response(self, context, **response_kwargs):
        data = json.dumps(context)
        response_kwargs['content_type'] = 'application/json'
        return HttpResponse(data, **response_kwargs)

    def form_invalid(self, form):
        response = super(AjaxableResponseMixin, self).form_invalid(form)
        if self.request.is_ajax():
            return self.render_to_json_response(form.errors, status=400)
        else:
            return response

    def form_valid(self, form):
        # We make sure to call the parent's form_valid() method because
        # it might do some processing (in the case of CreateView, it will
        # call form.save() for example).
        response = super(AjaxableResponseMixin, self).form_valid(form)
        if self.request.is_ajax():
            data = {
                'pk': self.object.pk,
            }
            return self.render_to_json_response(data)
        else:
            return response


class list_cert_page(generic.ListView):
    template_name = 'certprofile_list.html'
    context_object_name = 'latest_pki_cert'

    def get_queryset(self):
        """Return the cert profiles."""
        return CertProfile.objects.all()


class create_cert_profile(AjaxableResponseMixin, CreateView):
    template_name = 'certprofile_form.html'
    model = CertProfile
    success_url = '/pki/profile/'

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super(create_cert_profile, self).form_valid(form)


class update_cert_profile(UpdateView):
    template_name = 'certprofile_form.html'
    model = CertProfile
    success_url = '/pki/profile/'

class delete_cert_profile(DeleteView):
    template_name = 'certprofile_confirm_delete.html'
    model = CertProfile
    success_url = '/pki/profile/'


class list_cert_profile(generic.ListView):
    template_name = 'certprofile_list.html'
    context_object_name = 'cert_list'

    def get_queryset(self):
        """Return the profile list."""
        return CertProfile.objects.all()


class create_cert(AjaxableResponseMixin, CreateView):
    template_name = 'cert_form.html'
    model = Cert
    fields = ['cn','mail','st','organisation','country','profile']
    success_url = '/pki/cert/'

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super(create_cert, self).form_valid(form)


class update_cert(UpdateView):
    template_name = 'cert_form.html'
    model = Cert
    fields = ['cn','mail','st','organisation','country','profile','revoked']
    success_url = '/pki/cert/'

class delete_cert(DeleteView):
    template_name = 'cert_confirm_delete.html'
    model = Cert
    success_url = '/pki/cert/'


class list_cert(generic.ListView):
    template_name = 'cert_list.html'
    context_object_name = 'list_cert'

    def get_queryset(self):
        """Return the cert list."""
        return Cert.objects.all()


class create_ca(AjaxableResponseMixin, CreateView):
    template_name = 'ca_form.html'
    model = CA
    fields = ['cn','mail','organisation','ou','country','state','locality','key_type','key_size','digest','key_usage','extended_key_usage','days']
    success_url = '/pki/ca/'

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super(create_ca, self).form_valid(form)


class update_ca(UpdateView):
    template_name = 'ca_form.html'
    model = CA
    success_url = '/pki/ca/'

class delete_ca(DeleteView):
    template_name = 'ca_confirm_delete.html'
    model = CA
    success_url = '/pki/ca/'


class list_ca(generic.ListView):
    template_name = 'ca_list.html'
    context_object_name = 'list_ca'

    def get_queryset(self):
        """Return the ca list."""
        return CA.objects.all()


def sign_ca(request,pk):
    p = CA.objects.get(id=pk)
    if not p.ca_key:
        p.sign()
        p.save()
    return HttpResponseRedirect('/pki/ca/'+pk+'/')


def register(request):
    if request.method == 'POST':
        form = UserCreateForm(request.POST)
        if form.is_valid():
            new_user = form.save()
        return HttpResponseRedirect("/users/")
    else:
        form = UserCreateForm()
    return render(request, 'users_form.html', { 'form': form })


class update_user(UpdateView):
    template_name = 'users_form.html'
    model = User
    success_url = '/users/'
    fields = ['first_name', 'last_name','email','user_permissions','is_active','is_staff']


class delete_user(DeleteView):
    template_name = 'users_confirm_delete.html'
    model = User
    success_url = '/users/'


class list_user(generic.ListView):
    template_name = 'users_list.html'
    context_object_name = 'list_users'

    def get_queryset(self):
        """Return the ca list."""
        return User.objects.all()


def sign_cert(request,pk):
    p = Cert.objects.get(id=pk)
    if not p.pkey:
        p.sign()
        p.save()
    return HttpResponseRedirect('/pki/cert/'+pk+'/')


class revoke_cert(UpdateView):
    template_name = 'cert_revoke.html'
    model = Cert
    fields = ['CRLReason']

    def get_object(self, queryset=None):
        obj = Cert.objects.get(id=self.kwargs['pk'])
        return obj

    def form_valid(self, form):
        certificat = self.get_object()
        if not certificat.revoked:
            form.cleaned_data['revoked'] = datetime.datetime.now()
        crl = crypto.CRL()
        # Revoke current certificate
        now = datetime.datetime.now().strftime("%Y%m%d%H%M%SZ")
        revoked = crypto.Revoked()
        revoked.set_rev_date(now)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, certificat.x509)
        revoked.set_serial(str(x509.get_serial_number()))
        revoked.set_reason(form.cleaned_data['CRLReason'].encode('ascii'))
        crl.add_revoked(revoked)
        oldcert = CertRevoked(cn = certificat.cn, mail = certificat.mail, x509 = certificat.x509, st = certificat.st, organisation = certificat.organisation, country = certificat.country, pkey = certificat.pkey, profile = certificat.profile, valid_until = certificat.valid_until, date = certificat.date, userIssuerHashmd5 = certificat.userIssuerHashmd5, userIssuerHashsha1 = certificat.userIssuerHashsha1, userIssuerHashsha256 = certificat.userIssuerHashsha256, userIssuerHashsha512 = certificat.userIssuerHashsha512, revoked = datetime.datetime.now(),CRLReason = donnee['CRLReason'] )
        oldcert.save()
        certificate = crypto.load_certificate(FILETYPE_PEM,certificat.profile.ca.ca_cert)
        private_key = crypto.load_privatekey(FILETYPE_PEM, certificat.profile.ca.ca_key)
        for cert in Cert.objects.exclude(revoked__isnull=True):
            if certificat.profile != cert.profile:
                pass
            revoked = crypto.Revoked()
            revoked.set_rev_date(now)
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.x509)
            revoked.set_serial(str(x509.get_serial_number()))
            revoked.set_reason(cert.CRLReason.encode('ascii'))
            crl.add_revoked(revoked)
        open("%s" % certificat.profile.crl_path, "w").write(crl.export(certificate, private_key, type=FILETYPE_PEM))
        return super(revoke_cert, self).form_valid(form)


def download_cert(request,pk):
    cert = Cert.objects.get(id=pk)
    response = HttpResponse(content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename=' + string.replace(cert.cn, ' ', '_') + '.p12'
    password = generate_password()
    if cert.profile.p12_mail_password:
        cert.send_password(password)
    response.write(cert.pkcs12(password))
    return response

def send_cert(request,pk):
    cert = Cert.objects.get(id=pk)
    password = generate_password()
    if cert.profile.p12_mail_password:
        cert.send_cert(password)
    return HttpResponseRedirect('/pki/cert/'+pk+'/')


def generate_password():
    characters = string.ascii_letters + string.digits
    password =  "".join(random.choice(characters) for x in range(random.randint(8, 16)))
    return password


@csrf_exempt
def ocsp_server(request):
    ocspReq = rfc2560.OCSPRequest()
    content = request.body
    cr, rest = decoder.decode(content, asn1Spec=ocspReq)
    tbsRequest = cr.getComponentByName('tbsRequest')
    version = tbsRequest.getComponentByName('version')
    requestList = tbsRequest.getComponentByName('requestList')
    requestExtensions = tbsRequest.getComponentByName('requestExtensions')
    for extension in requestExtensions:
        extnID = extension.getComponentByName('extnID')
        critical = extension.getComponentByName('critical')
        extnValue = extension.getComponentByName('extnValue')
    for List in requestList:
        reqCert = List.getComponentByName('reqCert')
        hashAlgorithm = reqCert.getComponentByName('hashAlgorithm')
        algorithm = hashAlgorithm.getComponentByName('algorithm')
        issuerNameHash = reqCert.getComponentByName('issuerNameHash')
        issuerKeyHash = reqCert.getComponentByName('issuerKeyHash')
        serialNumber = reqCert.getComponentByName('serialNumber')
        issuerNameHash = issuerNameHash.prettyPrint().lstrip("0x")
        try:
            if algorithm.prettyPrint() == '1.3.14.3.2.26':
                cert = Cert.objects.get(userIssuerHashsha1 = issuerNameHash, id = serialNumber.prettyPrint())
            elif algorithm.prettyPrint() == '1.2.840.113549.2.5':
                cert = Cert.objects.get(userIssuerHashmd5 = issuerNameHash, id = serialNumber.prettyPrint())
            elif algorithm.prettyPrint() == '2.16.840.1.101.3.4.2.1':
                cert = Cert.objects.get(userIssuerHashsha256 = issuerNameHash, id = serialNumber.prettyPrint())
            elif algorithm.prettyPrint() == '2.16.840.1.101.3.4.2.3':
                cert = Cert.objects.get(userIssuerHashsha512 = issuerNameHash, id = serialNumber.prettyPrint())
            else:
                break
        except:
            ocspResp = rfc2560.OCSPResponse()
            ocspResp.setComponentByName('responseStatus', '2')
            response = HttpResponse(der_encoder.encode(ocspResp), content_type='application/ocsp-response')
            return response

    # Load CA Certificates
    certificat = crypto.load_certificate(crypto.FILETYPE_PEM, cert.profile.ca.ca_cert)
    private_key = crypto.load_privatekey(FILETYPE_PEM, cert.profile.ca.ca_key)

    # Prepare the answer
    singleResponse = rfc2560.SingleResponse()
    # Check the status of the certificate (CRL check to do)
    certStatus = rfc2560.CertStatus()
    if cert.CRLReason:
        revokedpos = certStatus.componentType.getPositionByName('revoked')
        revokedtype = certStatus.componentType.getTypeByPosition(revokedpos)
        revoked = revokedtype.clone()
        revoked.setComponentByName('revocationTime',time.strftime('%Y%m%d%H%M%SZ',time.gmtime(cert.revoked)))
        revoked.setComponentByName('revocationReason', cert.CRLReason.encode('ascii'))
        certStatus.setComponentByPosition(1,revoked)
    else:
        certStatus.setComponentByName('good')
    
    singleResponse.setComponentByName('certID',reqCert)
    singleResponse.setComponentByName('certStatus',certStatus)
    singleResponse.setComponentByName('thisUpdate',time.strftime('%Y%m%d%H%M%SZ',time.gmtime(time.time())))
    singleResponse.setComponentByName('nextUpdate',time.strftime('%Y%m%d%H%M%SZ',time.gmtime(time.time()+3600)))

    sequenceOfsingleResponse = univ.SequenceOf()
    sequenceOfsingleResponse.setComponentByPosition(0,singleResponse)

    responderID = rfc2560.ResponderID()

    # Create the HashKey of CA
    substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, certificat)
    certType = rfc2459.Certificate()
    certif, rest = decoder.decode(substrate, asn1Spec=certType)
    issuerTbsCertificate = certif.getComponentByName('tbsCertificate')
    issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName('subjectPublicKey')
    issuer_key_hash = univ.OctetString(hashlib.sha1(valueOnlyBitStringEncoder(issuerSubjectPublicKey)).digest())
    keypos = responderID.componentType.getPositionByName('byKey')
    keytype = responderID.componentType.getTypeByPosition(keypos)
    key = keytype.clone(issuer_key_hash)
    responderID.setComponentByPosition(1, key)

    # Create the responseData
    responseData = rfc2560.ResponseData()
    responseData.setComponentByName('version','v1')
    responseIDpos = responseData.componentType.getPositionByName('responderID')
    responseIDtype = responseData.componentType.getTypeByPosition(responseIDpos)
    responseID = responseIDtype.clone()
    responseID.setComponentByPosition(1, key)
    responseData.setComponentByName('responderID', responseID)
    responseData.setComponentByName('producedAt', time.strftime('%Y%m%d%H%M%SZ',time.gmtime(time.time())))
    responseData.setComponentByName('responses', sequenceOfsingleResponse)


    responseextensionpos = responseData.componentType.getPositionByName('responseExtensions')
    responseextensiontype = responseData.componentType.getTypeByPosition(responseextensionpos)
    responseextension = responseextensiontype.clone()
    responseextension.setComponentByPosition(0,requestExtensions[0])
    responseData.setComponentByName('responseExtensions',responseextension)

    algorithmIdentifier = rfc2459.AlgorithmIdentifier()
    algorithmIdentifier.setComponentByName('algorithm',rfc2459.sha1WithRSAEncryption)

    # Create basicOCSPResponse
    basicOCSPResponse = rfc2560.BasicOCSPResponse()
    basicOCSPResponse.setComponentByName('tbsResponseData',responseData)
    basicOCSPResponse.setComponentByName('signatureAlgorithm', algorithmIdentifier)

    #Sign responseData with CA private key
    signature = crypto.sign(private_key, der_encoder.encode(responseData), 'sha1')
    sig = univ.BitString("'%s'B" % BytesToBin(signature))
    basicOCSPResponse.setComponentByName('signature', sig)

    # Add CA public key certificate
    certpos = basicOCSPResponse.componentType.getPositionByName('certs')
    certtype = basicOCSPResponse.componentType.getTypeByPosition(certpos)
    certifics = certtype.clone()
    certifics.setComponentByPosition(0,certif)
    basicOCSPResponse.setComponentByName('certs', certifics)

    # Create responseBytes
    response = der_encoder.encode(basicOCSPResponse)
    responseBytes = rfc2560.ResponseBytes()
    responseBytes.setComponentByName('responseType', rfc2560.id_pkix_ocsp_basic)
    responseBytes.setComponentByName('response', response)

    # Create OCSPResponse
    ocspResp = rfc2560.OCSPResponse()
    ocspResp.setComponentByName('responseStatus', '0')
    attrpos = ocspResp.componentType.getPositionByName('responseBytes')
    attrtype = ocspResp.componentType.getTypeByPosition(attrpos)
    attr = attrtype.clone()
    attr.setComponentByName('responseType', rfc2560.id_pkix_ocsp_basic)
    attr.setComponentByName('response', response)
    ocspResp.setComponentByName('responseBytes', attr)

    #Prepare the answer
    response = HttpResponse(der_encoder.encode(ocspResp), content_type='application/ocsp-response')

    return response


class certWizard(SessionWizardView):
    form_list = [CertForm1, CertForm2]
    template_name = 'wizard.html'

    def done(self, form_list, **kwargs):
        form_data = [form.cleaned_data for form in form_list]
        data = dict(form_data[0].items() + form_data[1].items())
        if not 'profile' in data:
            restdefault = rest.objects.get(pk=1)
            data['profile'] = restdefault.profile
        serializer = CertSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            certif = Cert.objects.get(cn=data['cn'])
            certif.sign()
            certif.save()
        response = HttpResponse(content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=' + string.replace(certif.cn, ' ', '_') + '.p12'
        response.write(certif.pkcs12(data['password']))
        return response

class InitWizard(SessionWizardView):
    form_list = [CAForm, CertProfileForm, restForm]
    template_name = 'wizardca.html'

    def done(self, form_list, **kwargs):
        form_data = [form.cleaned_data for form in form_list]
        ca_data = dict(form_data[0].items())
        profile_data = dict(form_data[1].items())
        rest_data = dict(form_data[2].items())
        serializer = CaSerializer(data=ca_data)
        if serializer.is_valid():
            serializer.save()
            certif = CA.objects.get(cn=str(ca_data['cn']))
            certif.sign()
            certif.save()
        profile_data['ca'] = certif.cn
        serializer2 = CertProfileSerializer(data=profile_data)
        if serializer2.is_valid():
            serializer2.save()
            profile = CertProfile.objects.get(name=str(profile_data['name']))
        rest_data['profile'] = profile.name
        serializer3 = restSerializer(data=rest_data)
        burmp = serializer3.is_valid()
        bermot
        if serializer3.is_valid():
            serializer3.save()
        return HttpResponseRedirect("/pki/")

class JSONResponse(HttpResponse):
    """
    An HttpResponse that renders its content into JSON.
    """
    def __init__(self, data, **kwargs):
        content = JSONRenderer().render(data)
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)


def valid_rest_user(request,cert):
    try:
        restprofils = rest.objects.filter(profile=cert.profile)
    except AttributeError:
        profile = CertProfile.objects.get(name=cert)
        restprofil = rest.objects.get(profile=profile)
        if request.user in restprofil.allowed_users.all():
            return 1
        return 0
    for restprofil in restprofils:
        if request.user in restprofil.allowed_users.all():
            return 1
    return 0
#    except rest.DoesNotExist:
#        return 0

class cert_detail(APIView):
    authentication_classes = (SessionAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    """
    Retrieve, update or delete a code snippet.
    """
    model = Cert

    def get_object(self, pk):
        try:
            return Cert.objects.get(cn=pk)
        except Cert.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        cert = self.get_object(pk)
        if valid_rest_user(request,cert):
            serializer = CertSerializer(cert)
            return Response(serializer.data , status=None, template_name=None, headers=None, content_type=None)
        return Response(status=status.HTTP_401_UNAUTHORIZED)
 
    def put(self, request, pk, format=None):
        cert = self.get_object(pk)
        if valid_rest_user(request,cert):
            serializer = CertSerializer(cert, data=request.DATA)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    def delete(self, request, pk, format=None):
        cert = self.get_object(pk)
        if valid_rest_user(request,cert):
            cert.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    def post(self, request, pk):
        donnee = request.DATA.copy()
        donnee['cn'] = pk
        try:
            certificat = Cert.objects.get(cn=pk)
        except Cert.DoesNotExist:
            response = create_certificate(request,donnee)
            return response
        if valid_rest_user(request,certificat):
            response = HttpResponse(certificat.pkcs12(str(donnee['pwd'])), content_type='application/x-pkcs12')
            response['Content-Disposition'] = "attachment; filename={}.p12".format(donnee['cn'])
            return response
        else:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

def create_certificate(request,donnee):
    if not 'profile' in donnee:
        restdefault = rest.objects.get(pk=1)
        donnee['profile'] = restdefault.profile
    if valid_rest_user(request,donnee['profile']):
        serializer = CertSerializer(data=donnee)
        if serializer.is_valid():
            serializer.save()
            certificat = Cert.objects.get(cn=donnee['cn'])
            certificat.sign()
            certificat.save()
            response = HttpResponse(certificat.pkcs12(str(donnee['pwd'])), content_type='application/x-pkcs12')
            response['Content-Disposition'] = "attachment; filename={}.p12".format(donnee['cn'])
            return response
        else:
            return Response(status=status.HTTP_204_NO_CONTENT)
    else:
        return Response(status=status.HTTP_401_UNAUTHORIZED)


class cert_list(APIView):
    permission_classes = (permissions.DjangoModelPermissions,)
    """
    List all code snippets, or create a new snippet.
    """
    queryset = Cert.objects.all()

    def get(self, request, pk, format=None):
        rest_entry = rest.objects.get(name=pk)
        if request.user in rest_entry.allowed_users.all():
            certs = Cert.objects.filter(profile=rest_entry.profile)
            serializer = CertSerializer(certs, many=True)
            return Response(serializer.data)
        else:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

    def post(self, request, pk, format=None, **kwargs):
        rest_entry = rest.objects.get(name=pk)
        if request.user in rest_entry.allowed_users.all():
            serializer = CertSerializer(data=request.DATA)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_401_UNAUTHORIZED)


class create_rest(AjaxableResponseMixin, CreateView):
    template_name = 'rest_form.html'
    model = rest
    success_url = '/pki/rest/'

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super(create_rest, self).form_valid(form)


class update_rest(UpdateView):
    template_name = 'rest_form.html'
    model = rest
    success_url = '/pki/rest/'

class delete_rest(DeleteView):
    template_name = 'rest_confirm_delete.html'
    model = rest
    success_url = '/pki/rest/'


class list_rest(generic.ListView):
    template_name = 'rest_list.html'
    context_object_name = 'rest_list'

    def get_queryset(self):
        """Return the rest list."""
        return rest.objects.all()

class create_ldap(AjaxableResponseMixin, CreateView):
    template_name = 'ldap_form.html'
    model = LDAP
    success_url = '/pki/ldap/'

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super(create_ldap, self).form_valid(form)

class update_ldap(UpdateView):
    template_name = 'ldap_form.html'
    model = LDAP
    success_url = '/pki/ldap/'

class delete_ldap(DeleteView):
    template_name = 'ldap_confirm_delete.html'
    model = LDAP
    success_url = '/pki/ldap/'


class list_ldap(generic.ListView):
    template_name = 'ldap_list.html'
    context_object_name = 'ldap_list'

    def get_queryset(self):
        """Return the LDAP list."""
        return LDAP.objects.all()

class create_attribut(AjaxableResponseMixin, CreateView):
    template_name = 'attribut_form.html'
    model = Attrib
    success_url = '/pki/ldap/attribut/'

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super(create_attribut, self).form_valid(form)

class update_attribut(UpdateView):
    template_name = 'attribut_form.html'
    model = Attrib
    success_url = '/pki/ldap/attribut/'

class delete_attribut(DeleteView):
    template_name = 'attribut_confirm_delete.html'
    model = Attrib
    success_url = '/pki/ldap/attribut/'


class list_attribut(generic.ListView):
    template_name = 'attribut_list.html'
    context_object_name = 'attribut_list'

    def get_queryset(self):
        """Return the Attrib list."""
        return Attrib.objects.all()

class create_schema(AjaxableResponseMixin, CreateView):
    template_name = 'schema_form.html'
    model = SCHEMA
    success_url = '/pki/ldap/schema/'

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super(create_schema, self).form_valid(form)

class update_schema(UpdateView):
    template_name = 'schema_form.html'
    model = SCHEMA
    success_url = '/pki/ldap/schema/'

class delete_schema(DeleteView):
    template_name = 'schema_confirm_delete.html'
    model = SCHEMA
    success_url = '/pki/ldap/schema/'


class list_schema(generic.ListView):
    template_name = 'schema_list.html'
    context_object_name = 'schema_list'

    def get_queryset(self):
        """Return the SCHEMA list."""
        return SCHEMA.objects.all()

def ldap_users_list(request,pk):
    ldap_users = LDAP.objects.get(id=pk)
    users = ldap_users.all_users()
    return render_to_response('ldap_users_list.html',{'users': users, 'pk': pk},context_instance=RequestContext(request))

def ldap_groups_list(request,pk):
    ldap = LDAP.objects.get(id=pk)
    return ldap.all_groups()

class cert_revoke(APIView):
    authentication_classes = (SessionAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    """
    Revoke certificate.
    """
    models = Cert

    def get_object(self, pk):
        try:
            return Cert.objects.get(cn=pk)
        except Cert.DoesNotExist:
            raise Http404

    def post(self, request, pk):
        certificat = self.get_object(pk)
        if valid_rest_user(request,certificat):
            donnee = request.data.copy()
            crl = crypto.CRL()
            # Revoke current certificate
            now = datetime.datetime.now().strftime("%Y%m%d%H%M%SZ")
            revoked = crypto.Revoked()
            revoked.set_rev_date(now)
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, certificat.x509)
            revoked.set_serial(str(x509.get_serial_number()))
            revoked.set_reason(donnee['CRLReason'].encode('ascii'))
            crl.add_revoked(revoked)
            oldcert = CertRevoked(cn = certificat.cn, mail = certificat.mail, x509 = certificat.x509, st = certificat.st, organisation = certificat.organisation, country = certificat.country, pkey = certificat.pkey, profile = certificat.profile, valid_until = certificat.valid_until, date = certificat.date, userIssuerHashmd5 = certificat.userIssuerHashmd5, userIssuerHashsha1 = certificat.userIssuerHashsha1, userIssuerHashsha256 = certificat.userIssuerHashsha256, userIssuerHashsha512 = certificat.userIssuerHashsha512, revoked = datetime.datetime.now(),CRLReason = donnee['CRLReason'] )
            oldcert.save()
            certificate = crypto.load_certificate(FILETYPE_PEM,certificat.profile.ca.ca_cert)
            private_key = crypto.load_privatekey(FILETYPE_PEM, certificat.profile.ca.ca_key)
            certificat.delete()
            for cert in CertRevoked.objects.exclude(revoked__isnull=True):
                if oldcert.profile != cert.profile:
                    pass
                revoked = crypto.Revoked()
                revoked.set_rev_date(now)
                x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.x509)
                revoked.set_serial(str(x509.get_serial_number()))
                revoked.set_reason(cert.CRLReason.encode('ascii'))
                crl.add_revoked(revoked)
            open("%s" % oldcert.profile.crl_path, "w").write(crl.export(certificate, private_key, type=FILETYPE_PEM))
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_401_UNAUTHORIZED)
