from django import forms
from .models import TrustedDevice, NetworkSlice, SliceAccessPolicy
class DeviceRegistrationForm(forms.ModelForm):
    class Meta:
        model = TrustedDevice
        fields = ['name', 'device_type', 'device_id', 'security_level', 'location']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter device name'
            }),
            'device_id': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter unique device ID'
            }),
            'device_type': forms.Select(attrs={'class': 'form-control'}),
            'security_level': forms.Select(attrs={'class': 'form-control'}),
            'location': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Optional: device location'
            }),
        }
    
    def clean_device_id(self):
        device_id = self.cleaned_data.get('device_id')
        if TrustedDevice.objects.filter(device_id=device_id).exists():
            raise forms.ValidationError("Device ID already exists in the system.")
        return device_id



class NetworkSliceForm(forms.ModelForm):
    class Meta:
        model = NetworkSlice
        fields = ['name', 'slice_id', 'slice_type', 'priority', 'max_latency', 'min_bandwidth', 'security_level']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Emergency Response Slice'}),
            'slice_id': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'SLICE-EMERG-001'}),
            'slice_type': forms.Select(attrs={'class': 'form-control'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
            'max_latency': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': '10'}),
            'min_bandwidth': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': '100'}),
            'security_level': forms.Select(attrs={'class': 'form-control'}),
        }

class SliceAccessPolicyForm(forms.ModelForm):
    class Meta:
        model = SliceAccessPolicy
        fields = ['slice', 'allowed_device_types', 'required_security_level', 'requires_approval']
        widgets = {
            'slice': forms.Select(attrs={'class': 'form-control'}),
            'required_security_level': forms.Select(attrs={'class': 'form-control'}),
            'requires_approval': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['allowed_device_types'] = forms.MultipleChoiceField(
            choices=TrustedDevice.DEVICE_TYPES,
            widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-check-input'}),
            help_text="Select which device types can access this slice"
        )