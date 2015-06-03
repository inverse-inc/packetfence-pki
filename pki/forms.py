from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.forms import ModelForm
from django import forms
from pki.models import *

class CertForm1(forms.Form):
    cn = forms.CharField(max_length=100)
    mail = forms.EmailField()
    st = forms.CharField(max_length=100)
    organisation = forms.CharField(max_length=100)
    country = forms.CharField(max_length=100)

class CertForm2(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput())


class UserCreateForm(UserCreationForm):
    # declare the fields you will show
    username = forms.CharField(label="Your Username")
    # first password field
    password1 = forms.CharField(label="Your Password")
    # confirm password field
    password2 = forms.CharField(label="Repeat Your Password")
    email = forms.EmailField(label = "Email Address")
    first_name = forms.CharField(label = "Name")
    last_name = forms.CharField(label = "Surname")
    # this sets the order of the fields

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "username", "password1", "password2", )
    # this redefines the save function to include the fields you added

    def save(self, commit=True):
        user = super(UserCreateForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        user.first_name = self.cleaned_data["first_name"]
        user.last_name = self.cleaned_data["last_name"]
        if commit:
            user.save()
            return user

class CAForm(ModelForm):
    class Meta:
        model = CA
        fields = ['cn','mail','organisation','ou','country','state','locality','key_type','key_size','digest','key_usage','extended_key_usage','days']
