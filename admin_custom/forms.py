from django import forms
from django.core.validators import RegexValidator
from datetime import datetime


from django import forms
from django.core.validators import RegexValidator
from datetime import datetime
from .models import VM


class PaymentForm(forms.Form):
    vm_id = forms.CharField(max_length=4)
    name = forms.CharField(max_length=100)
    email = forms.EmailField()
    card_number = forms.CharField(max_length=16, validators=[
        RegexValidator(r'^\d{16}$', 'Invalid credit card number')
    ])
    exp_month = forms.CharField(max_length=2, validators=[
        RegexValidator(r'^\d{2}$', 'Invalid expiration month')
    ])
    exp_year = forms.CharField(max_length=4, validators=[
        RegexValidator(r'^\d{4}$', 'Invalid expiration year')
    ])
    cvv = forms.CharField(max_length=3, validators=[
        RegexValidator(r'^\d{3}$', 'Invalid CVV')
    ])

    def clean_vm_id(self):
        vm_id = self.cleaned_data.get('vm_id')
        try:
            vm = VM.objects.get(id=vm_id)
        except VM.DoesNotExist:
            raise forms.ValidationError("Invalid VM ID")
        if vm.payed:
            raise forms.ValidationError("The specified VM has already been paid for")
        return vm_id

    def clean(self):
        cleaned_data = super().clean()
        exp_month = cleaned_data.get('exp_month')
        exp_year = cleaned_data.get('exp_year')

        if exp_month and exp_year:
            expiration_date = datetime.strptime(f"{exp_month}/{exp_year}", '%m/%Y')
            if expiration_date < datetime.now():
                raise forms.ValidationError("The credit card has expired")


from django.contrib.auth.models import User

from django import forms
from django.contrib.auth.forms import UserCreationForm

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from django import forms
from django.contrib.auth.forms import UserCreationForm

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model


from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    username = forms.CharField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_email(self):
        email = self.cleaned_data["email"]
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already taken.")
        return email

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("This username is already taken.")
        return username



