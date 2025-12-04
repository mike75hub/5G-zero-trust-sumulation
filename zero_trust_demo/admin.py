from django.contrib import admin
from .models import TrustedDevice, AuthenticationLog, SecurityPolicy, NetworkSlice, SliceAccessPolicy, SliceAccessLog

@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display = ['name', 'device_id', 'device_type', 'security_level', 'status', 'is_active', 'last_authentication']
    list_filter = ['device_type', 'security_level', 'status', 'is_active', 'created_at']
    search_fields = ['name', 'device_id', 'location']
    readonly_fields = ['created_at', 'last_authentication', 'failed_attempts']
    actions = ['approve_devices', 'lock_devices', 'reset_attempts']
    
    fieldsets = (
        ('Device Information', {
            'fields': ('name', 'device_type', 'device_id', 'location')
        }),
        ('Security Configuration', {
            'fields': ('secret_key', 'security_level', 'status', 'is_active')
        }),
        ('Authentication History', {
            'fields': ('failed_attempts', 'last_authentication', 'created_at'),
            'classes': ('collapse',)
        }),
    )
    
    def approve_devices(self, request, queryset):
        updated = queryset.update(status='APPROVED')
        self.message_user(request, f'{updated} devices approved.')
    approve_devices.short_description = "Approve selected devices"
    
    def lock_devices(self, request, queryset):
        updated = queryset.update(status='LOCKED')
        self.message_user(request, f'{updated} devices locked.')
    lock_devices.short_description = "Lock selected devices"
    
    def reset_attempts(self, request, queryset):
        updated = queryset.update(failed_attempts=0)
        self.message_user(request, f'{updated} devices reset.')
    reset_attempts.short_description = "Reset failed attempts"

@admin.register(AuthenticationLog)
class AuthenticationLogAdmin(admin.ModelAdmin):
    list_display = ['device', 'timestamp', 'success', 'ip_address', 'reason']
    list_filter = ['success', 'timestamp', 'device__device_type']
    search_fields = ['device__name', 'device__device_id', 'ip_address', 'reason']
    readonly_fields = ['timestamp']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False

@admin.register(SecurityPolicy)
class SecurityPolicyAdmin(admin.ModelAdmin):
    list_display = ['name', 'max_failed_attempts', 'session_timeout', 'requires_approval', 'auto_lockout'] 
    
@admin.register(NetworkSlice)
class NetworkSliceAdmin(admin.ModelAdmin):
    list_display = ['name', 'slice_id', 'slice_type', 'priority', 'is_active', 'created_at']
    list_filter = ['slice_type', 'priority', 'is_active', 'created_at']
    search_fields = ['name', 'slice_id']

@admin.register(SliceAccessPolicy)
class SliceAccessPolicyAdmin(admin.ModelAdmin):
    list_display = ['slice', 'required_security_level', 'requires_approval']
    list_filter = ['required_security_level', 'requires_approval']

@admin.register(SliceAccessLog)
class SliceAccessLogAdmin(admin.ModelAdmin):
    list_display = ['device', 'slice', 'access_granted', 'timestamp']
    list_filter = ['access_granted', 'timestamp']
    readonly_fields = ['timestamp'] 