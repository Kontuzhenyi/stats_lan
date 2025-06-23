# macapp/forms.py
from django import forms

class MacForm(forms.Form):
    mac = forms.CharField(
        label="MAC Address",
        max_length=17,
        help_text="Format: XX:XX:XX:XX:XX:XX (e.g., A8:A1:59:8F:1A:F8)",
        required=True
    )
    description = forms.CharField(
        label="Description",
        widget=forms.Textarea,
        required=True
    )

# class IsThereMacForm(forms.Form):
#     mac_address = forms.CharField(
#         label='MAC-адрес',
#         max_length=17,
#         help_text='Введите MAC-адрес в формате XX:XX:XX:XX:XX:XX'
#     )