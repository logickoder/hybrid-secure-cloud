from typing import ClassVar

from django import forms
from django.contrib.auth.forms import UserCreationForm, UsernameField
from django.contrib.auth.models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ('username', 'email')
        field_classes: ClassVar[dict[str, type[UsernameField]]] = {'username': UsernameField}


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)


class TotpForm(forms.Form):
    code = forms.CharField(
        max_length=7,
        widget=forms.TextInput(attrs={'inputmode': 'numeric', 'autocomplete': 'one-time-code', 'autofocus': True}),
    )
