from django import forms


class AddUserForm(forms.Form):
    name = forms.CharField()
    email = forms.EmailField()

