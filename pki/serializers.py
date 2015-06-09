from django.contrib.auth.models import User
from django.forms import widgets
from rest_framework import serializers
from pki.models import *

class restSerializer(serializers.ModelSerializer):
    profile = serializers.SlugRelatedField(queryset=CertProfile.objects.all(), slug_field = 'name')
    allowed_users = serializers.SlugRelatedField(many=True, queryset=User.objects.all(), slug_field = 'username')

    class Meta:
        model = rest

class CertProfileSerializer(serializers.ModelSerializer):
    ca = serializers.SlugRelatedField(queryset=CA.objects.all(), slug_field = 'cn')

    class Meta:
        model = CertProfile

class CertSerializer(serializers.ModelSerializer):
    profile = serializers.SlugRelatedField(queryset=CertProfile.objects.all(), slug_field = 'name')

    class Meta:
        model = Cert
        fields = ('cn', 'mail', 'st', 'organisation', 'country', 'x509', 'profile')

class CaSerializer(serializers.ModelSerializer):

    class Meta:
        model = CA
        fields = ['cn','mail','organisation','ou','country','state','locality','key_type','key_size','digest','key_usage','extended_key_usage','days']
