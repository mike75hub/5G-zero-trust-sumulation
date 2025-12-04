from django.db import models
from django.utils import timezone
import secrets
import hashlib

class TrustedDevice(models.Model):
    DEVICE_TYPES = [
        ('SMARTPHONE', 'Smartphone'),
        ('IOT_SENSOR', 'IoT Sensor'),
        ('SMART_WATCH', 'Smart Watch'),
        ('VEHICLE', 'Connected Vehicle'),
        ('MEDICAL', 'Medical Device'),
        ('EMERGENCY', 'Emergency Service'),
        ('INDUSTRIAL', 'Industrial IoT'),
    ]
    
    SECURITY_LEVELS = [
        ('LOW', 'Low - Basic IoT'),
        ('MEDIUM', 'Medium - Personal Devices'),
        ('HIGH', 'High - Enterprise'),
        ('MAXIMUM', 'Maximum - Critical Infrastructure'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending Approval'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('SUSPENDED', 'Suspended'),
        ('LOCKED', 'Locked'),
    ]
    
    name = models.CharField(max_length=100)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPES)
    device_id = models.CharField(max_length=100, unique=True)
    secret_key = models.CharField(max_length=100)
    security_level = models.CharField(max_length=20, choices=SECURITY_LEVELS, default='MEDIUM')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    last_authentication = models.DateTimeField(null=True, blank=True)
    failed_attempts = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    location = models.CharField(max_length=100, blank=True)
    
    def generate_secret_key(self):
        return secrets.token_urlsafe(16)
    
    def save(self, *args, **kwargs):
        if not self.secret_key:
            self.secret_key = self.generate_secret_key()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.name} ({self.device_type})"
    
    class Meta:
        verbose_name = "Trusted Device"
        verbose_name_plural = "Trusted Devices"

class AuthenticationLog(models.Model):
    device = models.ForeignKey(TrustedDevice, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    reason = models.CharField(max_length=200, blank=True)
    
    def __str__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"{self.device.device_id} - {status} - {self.timestamp}"

class SecurityPolicy(models.Model):
    name = models.CharField(max_length=100)
    max_failed_attempts = models.IntegerField(default=3)
    session_timeout = models.IntegerField(default=30)  # minutes
    requires_approval = models.BooleanField(default=True)
    auto_lockout = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name


class NetworkSlice(models.Model):
    SLICE_TYPES = [
        ('EMERGENCY', 'Emergency Services'),
        ('VIDEO', 'Video Streaming'),
        ('IOT', 'IoT Devices'),
        ('ENTERPRISE', 'Enterprise'),
        ('PUBLIC', 'Public Safety'),
        ('INDUSTRIAL', 'Industrial IoT'),
    ]
    
    PRIORITY_LEVELS = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    name = models.CharField(max_length=100)
    slice_id = models.CharField(max_length=50, unique=True)
    slice_type = models.CharField(max_length=20, choices=SLICE_TYPES)
    priority = models.CharField(max_length=20, choices=PRIORITY_LEVELS, default='MEDIUM')
    max_latency = models.IntegerField(help_text="Maximum latency in milliseconds")  # ms
    min_bandwidth = models.IntegerField(help_text="Minimum bandwidth in Mbps")  # Mbps
    security_level = models.CharField(max_length=20, choices=TrustedDevice.SECURITY_LEVELS, default='HIGH')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} ({self.slice_type})"
    
    class Meta:
        verbose_name = "Network Slice"
        verbose_name_plural = "Network Slices"

class SliceAccessPolicy(models.Model):
    slice = models.ForeignKey(NetworkSlice, on_delete=models.CASCADE)
    allowed_device_types = models.JSONField(default=list, help_text="List of allowed device types")
    required_security_level = models.CharField(max_length=20, choices=TrustedDevice.SECURITY_LEVELS)
    requires_approval = models.BooleanField(default=True)
    
    def __str__(self):
        return f"Policy for {self.slice.name}"

class SliceAccessLog(models.Model):
    device = models.ForeignKey(TrustedDevice, on_delete=models.CASCADE)
    slice = models.ForeignKey(NetworkSlice, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    access_granted = models.BooleanField(default=False)
    reason = models.CharField(max_length=200, blank=True)
    bandwidth_used = models.FloatField(null=True, blank=True)  # Mbps
    latency = models.FloatField(null=True, blank=True)  # ms
    
    def __str__(self):
        status = "GRANTED" if self.access_granted else "DENIED"
        return f"{self.device.device_id} -> {self.slice.slice_id}: {status}"