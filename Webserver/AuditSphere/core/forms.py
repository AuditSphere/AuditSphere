from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.conf import settings  # Import settings
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.apps import apps
from django.core.exceptions import ValidationError


class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        'placeholder': 'Your email',
        'class': 'w-full py-4 px-6 rounded-xl text-gray-600'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': 'Your password',
        'class': 'w-full py-4 px-6 rounded-xl text-gray-600'
    }))
    
class PasswordResetRequestForm(PasswordResetForm):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'placeholder': 'Your email address',
            'class': 'w-full py-4 px-6 rounded-xl text-gray-600'
        })
    )

class SetNewPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'New password',
            'class': 'w-full py-4 px-6 rounded-xl text-gray-600'
        })
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Repeat new password',
            'class': 'w-full py-4 px-6 rounded-xl text-gray-600'
        })
    )
