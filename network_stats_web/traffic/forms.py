# macapp/forms.py
from django import forms
from .models import MacAddress, Room, Meter, Reading

class MacForm(forms.Form):
    mac = forms.CharField(
        label="MAC Address",
        max_length=17,
        help_text="Format: XX:XX:XX:XX:XX:XX (e.g., A8:A1:59:8F:1A:F8)",
        required=True
    )
    description = forms.CharField(
        label="Description",
        widget=forms.Textarea(attrs={'rows': 1}),
        required=True
    )

# class IsThereMacForm(forms.Form):
#     mac_address = forms.CharField(
#         label='MAC-адрес',
#         max_length=17,
#         help_text='Введите MAC-адрес в формате XX:XX:XX:XX:XX:XX'
#     )

class MacAddressForm(forms.ModelForm):
    class Meta:
        model = MacAddress
        fields = ['description']
        widgets = {
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 1}),
        }

class MeterReadingForm(forms.Form):
    room_id = forms.ModelChoiceField(
        queryset=Room.objects.exclude(name__in=['201н', '202н', '203н']).order_by('name'),
        label='Комната',
        empty_label='Выберите комнату',
        required=True, # Поле обязательно для заполнения, нельзя оставить пустым
    )
    meter_id = forms.ModelChoiceField(
        queryset=Meter.objects.none(), # Изначально список пустой
        label='Счетчик',
        empty_label='Выберите счетчик',
        required=True
    )
    value = forms.DecimalField(
        max_digits=10,
        # decimal_places=2,
        label='Показание',
        min_value=1,
        required=True
    )
    reading_date = forms.DateField(
        label='Дата показания',
        widget=forms.DateInput(attrs={'type': 'date'}),
        required=True
    )

    def __init__(self, *args, **kwargs):
        room_id = kwargs.pop('room_id', None) # Извлекает room_id из словаря kwargs переданного при создании формы
        meter_id = kwargs.pop('meter_id', None)
        super().__init__(*args, **kwargs) # Вызывает конструктор класса forms.Form
        if room_id:
            self.fields['meter_id'].queryset = Meter.objects.filter(room=room_id) # Фильтруем счетчики
        if meter_id:
            try:
                last_reading = Reading.objects.filter(meter=meter_id).order_by('-reading_date').first()
                if last_reading:
                    self.fields['value'].initial = last_reading.value
            except (ValueError, TypeError):
                pass  # Если meter_id некорректен, оставляем value пустым
