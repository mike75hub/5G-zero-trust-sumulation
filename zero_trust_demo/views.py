from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count, Q, Avg
from django.db.models.functions import TruncDate
from datetime import datetime, timedelta
import json
from .models import TrustedDevice, AuthenticationLog, NetworkSlice, SliceAccessPolicy, SliceAccessLog
from .forms import DeviceRegistrationForm, NetworkSliceForm, SliceAccessPolicyForm

def dashboard(request):
    """Enhanced dashboard with statistics"""
    total_devices = TrustedDevice.objects.count()
    approved_devices = TrustedDevice.objects.filter(status='APPROVED').count()
    pending_devices = TrustedDevice.objects.filter(status='PENDING').count()
    locked_devices = TrustedDevice.objects.filter(status='LOCKED').count()
    
    # Recent authentication attempts
    recent_logs = AuthenticationLog.objects.select_related('device').order_by('-timestamp')[:10]
    
    # Device type distribution
    device_stats = TrustedDevice.objects.values('device_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Recent slice access attempts
    recent_slice_access = SliceAccessLog.objects.select_related('device', 'slice').order_by('-timestamp')[:5]
    
    context = {
        'total_devices': total_devices,
        'approved_devices': approved_devices,
        'pending_devices': pending_devices,
        'locked_devices': locked_devices,
        'recent_logs': recent_logs,
        'device_stats': device_stats,
        'recent_slice_access': recent_slice_access,
    }
    return render(request, 'zero_trust_demo/dashboard.html', context)

def zero_trust_auth(request):
    """Main authentication """
    context = {}
    
    if request.method == 'POST':
        device_name = request.POST.get('device_name', '').strip()
        device_id = request.POST.get('device_id', '').strip()
        secret_key = request.POST.get('secret_key', '').strip()
        action = request.POST.get('action', 'authenticate')
        
        # Get client info for logging
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        if action == 'authenticate':
            try:
                device = TrustedDevice.objects.get(device_id=device_id)
                
                # Create authentication log
                auth_log = AuthenticationLog(
                    device=device,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Check device status
                if device.status == 'LOCKED':
                    auth_log.success = False
                    auth_log.reason = "Device locked due to security violations"
                    auth_log.save()
                    messages.error(request, "🚫 Access DENIED! Device temporarily locked due to security violations.")
                    context['access_granted'] = False
                    
                elif device.status != 'APPROVED':
                    auth_log.success = False
                    auth_log.reason = f"Device status: {device.status}"
                    auth_log.save()
                    messages.warning(request, f"⚠️ Device recognized but status: {device.get_status_display()}.")
                    context['access_granted'] = False
                    
                # Check secret key
                elif device.secret_key == secret_key:
                    # Successful authentication
                    device.last_authentication = timezone.now()
                    device.failed_attempts = 0
                    device.save()
                    
                    auth_log.success = True
                    auth_log.reason = "Successful authentication"
                    auth_log.save()
                    
                    context['access_granted'] = True
                    context['device'] = device
                    messages.success(request, f"✅ Access GRANTED! Zero-trust authentication passed for {device.name}.")
                    
                else:
                    # Failed attempt
                    device.failed_attempts += 1
                    if device.failed_attempts >= 3:
                        device.status = 'LOCKED'
                        messages.error(request, "🔒 Device LOCKED! Too many failed authentication attempts.")
                    else:
                        messages.error(request, f"❌ Access DENIED! Invalid credentials. {3 - device.failed_attempts} attempts remaining.")
                    device.save()
                    
                    auth_log.success = False
                    auth_log.reason = "Invalid secret key"
                    auth_log.save()
                    context['access_granted'] = False
                    
            except TrustedDevice.DoesNotExist:
                # Log failed attempt for unknown device
                auth_log = AuthenticationLog(
                    device=None,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    reason="Unknown device ID"
                )
                auth_log.save()
                messages.error(request, "❌ Access DENIED! Device not found in trusted registry.")
                context['access_granted'] = False
        
        elif action == 'register':
            form = DeviceRegistrationForm(request.POST)
            if form.is_valid():
                device = form.save(commit=False)
                device.secret_key = device.generate_secret_key()
                device.save()
                messages.info(request, 
                    f"Device '{device.name}' registered successfully! "
                    f"Secret Key: <strong>{device.secret_key}</strong> - Awaiting administrator approval."
                )
            else:
                for error in form.errors.values():
                    messages.error(request, error)
    
    # Get sample devices for demonstration
    sample_devices = TrustedDevice.objects.filter(status='APPROVED')[:5]
    context['sample_devices'] = sample_devices
    context['form'] = DeviceRegistrationForm()
    
    return render(request, 'zero_trust_demo/zero_trust_auth.html', context)

def device_management(request):
    """device management console"""
    devices = TrustedDevice.objects.all().order_by('-created_at')
    
    if request.method == 'POST':
        device_id = request.POST.get('device_id')
        action = request.POST.get('action')
        
        try:
            device = TrustedDevice.objects.get(id=device_id)
            
            if action == 'approve':
                device.status = 'APPROVED'
                device.save()
                messages.success(request, f"Device '{device.name}' approved for network access!")
                
            elif action == 'reject':
                device.status = 'REJECTED'
                device.save()
                messages.warning(request, f"Device '{device.name}' rejected!")
                
            elif action == 'suspend':
                device.status = 'SUSPENDED'
                device.save()
                messages.warning(request, f"Device '{device.name}' suspended!")
                
            elif action == 'unlock':
                device.status = 'APPROVED'
                device.failed_attempts = 0
                device.save()
                messages.success(request, f"Device '{device.name}' unlocked!")
                
            elif action == 'reset_key':
                old_key = device.secret_key
                device.secret_key = device.generate_secret_key()
                device.save()
                messages.info(request, 
                    f"Secret key reset for '{device.name}'! "
                    f"Old: {old_key} → New: {device.secret_key}"
                )
                
            elif action == 'delete':
                device_name = device.name
                device.delete()
                messages.error(request, f"Device '{device_name}' permanently deleted!")
                
        except TrustedDevice.DoesNotExist:
            messages.error(request, "Device not found!")
    
    return render(request, 'zero_trust_demo/device_management.html', {'devices': devices})

def network_slicing_demo(request):
    """Network Slicing Security """
    context = {}
    
    # Get all slices and policies
    slices = NetworkSlice.objects.all()
    policies = SliceAccessPolicy.objects.select_related('slice')
    
    if request.method == 'POST':
        device_id = request.POST.get('device_id')
        slice_id = request.POST.get('slice_id')
        action = request.POST.get('action')
        
        if action == 'access_slice':
            try:
                device = TrustedDevice.objects.get(device_id=device_id)
                network_slice = NetworkSlice.objects.get(slice_id=slice_id)
                
                # Check if slice is active
                if not network_slice.is_active:
                    messages.error(request, f"❌ Slice '{network_slice.name}' is currently inactive.")
                    context['access_granted'] = False
                
                else:
                    # Check access policies
                    try:
                        policy = SliceAccessPolicy.objects.get(slice=network_slice)
                        
                        # Check device type
                        if device.device_type not in policy.allowed_device_types:
                            messages.error(request, f"❌ Access DENIED! {device.get_device_type_display()} devices cannot access {network_slice.name}.")
                            context['access_granted'] = False
                        
                        # Check security level
                        elif device.security_level != policy.required_security_level:
                            messages.error(request, f"❌ Access DENIED! This slice requires {policy.get_required_security_level_display()} security level.")
                            context['access_granted'] = False
                        
                        # Check device status
                        elif device.status != 'APPROVED':
                            messages.error(request, f"❌ Access DENIED! Device status: {device.get_status_display()}.")
                            context['access_granted'] = False
                        
                        else:
                            # Access granted!
                            messages.success(request, f"✅ Access GRANTED! {device.name} can use {network_slice.name} slice.")
                            context['access_granted'] = True
                            
                            # Log the access
                            SliceAccessLog.objects.create(
                                device=device,
                                slice=network_slice,
                                access_granted=True,
                                reason="All access policies satisfied",
                                bandwidth_used=network_slice.min_bandwidth * 0.8,  # Simulate usage
                                latency=network_slice.max_latency * 0.6  # Simulate latency
                            )
                    
                    except SliceAccessPolicy.DoesNotExist:
                        messages.error(request, f"❌ No access policy defined for {network_slice.name}.")
                        context['access_granted'] = False
                
                if not context.get('access_granted'):
                    # Log denied access
                    SliceAccessLog.objects.create(
                        device=device,
                        slice=network_slice,
                        access_granted=False,
                        reason="Access policy violation"
                    )
                
                context['device'] = device
                context['network_slice'] = network_slice
                
            except TrustedDevice.DoesNotExist:
                messages.error(request, "❌ Device not found in trusted registry.")
            except NetworkSlice.DoesNotExist:
                messages.error(request, "❌ Network slice not found.")
        
        elif action == 'create_slice':
            form = NetworkSliceForm(request.POST)
            if form.is_valid():
                slice_obj = form.save()
                messages.success(request, f"✅ Network slice '{slice_obj.name}' created successfully!")
            else:
                for error in form.errors.values():
                    messages.error(request, error)
        
        elif action == 'create_policy':
            policy_form = SliceAccessPolicyForm(request.POST)
            if policy_form.is_valid():
                policy = policy_form.save()
                messages.success(request, f"✅ Access policy created for {policy.slice.name}!")
            else:
                for error in policy_form.errors.values():
                    messages.error(request, error)
    
    # Forms for slice and policy creation
    context['slice_form'] = NetworkSliceForm()
    context['policy_form'] = SliceAccessPolicyForm()
    context['slices'] = slices
    context['policies'] = policies
    
    # Get recent slice access logs
    context['slice_logs'] = SliceAccessLog.objects.select_related('device', 'slice').order_by('-timestamp')[:10]
    
    return render(request, 'zero_trust_demo/network_slicing.html', context)

def slice_management(request):
    """Network Slice Management"""
    slices = NetworkSlice.objects.all().order_by('-created_at')
    policies = SliceAccessPolicy.objects.select_related('slice').all()
    
    if request.method == 'POST':
        slice_id = request.POST.get('slice_id')
        action = request.POST.get('action')
        
        try:
            network_slice = NetworkSlice.objects.get(id=slice_id)
            
            if action == 'toggle_active':
                network_slice.is_active = not network_slice.is_active
                network_slice.save()
                status = "activated" if network_slice.is_active else "deactivated"
                messages.success(request, f"Slice '{network_slice.name}' {status}!")
            
            elif action == 'delete_slice':
                slice_name = network_slice.name
                network_slice.delete()
                messages.error(request, f"Slice '{slice_name}' deleted!")
            
            elif action == 'delete_policy':
                policy_id = request.POST.get('policy_id')
                policy = SliceAccessPolicy.objects.get(id=policy_id)
                policy_name = f"Policy for {policy.slice.name}"
                policy.delete()
                messages.error(request, f"Access policy '{policy_name}' deleted!")
                
        except (NetworkSlice.DoesNotExist, SliceAccessPolicy.DoesNotExist):
            messages.error(request, "Slice or policy not found!")
    
    context = {
        'slices': slices,
        'policies': policies,
    }
    return render(request, 'zero_trust_demo/slice_management.html', context)

def security_monitor(request):
    """Enhanced security monitor with analytics"""
    total_attempts = AuthenticationLog.objects.count()
    successful_attempts = AuthenticationLog.objects.filter(success=True).count()
    failed_attempts = total_attempts - successful_attempts
    
    # Recent security events
    security_events = AuthenticationLog.objects.select_related('device').order_by('-timestamp')[:20]
    
    # Failed attempts by IP (potential threats)
    suspicious_ips = AuthenticationLog.objects.filter(success=False).values(
        'ip_address'
    ).annotate(
        failed_count=Count('id')
    ).filter(failed_count__gte=3).order_by('-failed_count')
    
    # Get last attempt timestamp for each suspicious IP
    for ip in suspicious_ips:
        last_attempt = AuthenticationLog.objects.filter(
            ip_address=ip['ip_address'], success=False
        ).order_by('-timestamp').first()
        ip['last_attempt'] = last_attempt.timestamp if last_attempt else None
    
    # Slice access security events
    slice_security_events = SliceAccessLog.objects.select_related('device', 'slice').order_by('-timestamp')[:15]
    
    # Security trends (last 24 hours) - FIXED: Use manual time ranges
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
    
    # Simple hourly aggregation without complex date formatting
    hourly_auth_attempts = []
    for hour in range(24):
        hour_start = twenty_four_hours_ago + timedelta(hours=hour)
        hour_end = hour_start + timedelta(hours=1)
        
        total = AuthenticationLog.objects.filter(
            timestamp__gte=hour_start,
            timestamp__lt=hour_end
        ).count()
        
        failed = AuthenticationLog.objects.filter(
            timestamp__gte=hour_start,
            timestamp__lt=hour_end,
            success=False
        ).count()
        
        hourly_auth_attempts.append({
            'hour': hour_start.hour,
            'total': total,
            'failed': failed
        })
    
    context = {
        'total_attempts': total_attempts,
        'successful_attempts': successful_attempts,
        'failed_attempts': failed_attempts,
        'security_events': security_events,
        'suspicious_ips': suspicious_ips,
        'slice_security_events': slice_security_events,
        'hourly_auth_attempts': hourly_auth_attempts,
    }
    return render(request, 'zero_trust_demo/security_monitor.html', context)

def device_analytics(request):
    """Enhanced analytics with graphs data"""
    # Device status distribution
    status_distribution = TrustedDevice.objects.values('status').annotate(
        count=Count('id')
    ).order_by('status')
    
    # Device type distribution
    type_distribution = TrustedDevice.objects.values('device_type').annotate(
        count=Count('id')
    ).order_by('device_type')
    
    # Authentication analytics
    total_attempts = AuthenticationLog.objects.count()
    successful_attempts = AuthenticationLog.objects.filter(success=True).count()
    failed_attempts = total_attempts - successful_attempts
    
    # Authentication success rate
    auth_success_rate = 0
    if total_attempts > 0:
        auth_success_rate = (successful_attempts / total_attempts) * 100
    
    # Recent registrations
    recent_registrations = TrustedDevice.objects.order_by('-created_at')[:10]
    
    # Network slicing analytics
    slice_access_stats = SliceAccessLog.objects.values('slice__name').annotate(
        total_attempts=Count('id'),
        granted_attempts=Count('id', filter=Q(access_granted=True)),
        avg_bandwidth=Avg('bandwidth_used'),
        avg_latency=Avg('latency')
    ).order_by('-total_attempts')
    
    # Device type access patterns
    device_access_patterns = SliceAccessLog.objects.values(
        'device__device_type'
    ).annotate(
        total_attempts=Count('id'),
        success_count=Count('id', filter=Q(access_granted=True))
    ).order_by('-total_attempts')
    
    # Calculate success rates for device access patterns
    for pattern in device_access_patterns:
        pattern['success_rate'] = (pattern['success_count'] / pattern['total_attempts'] * 100) if pattern['total_attempts'] > 0 else 0
    
    # Time-based analytics (last 7 days) - FIXED: Use Django's TruncDate
    seven_days_ago = timezone.now() - timedelta(days=7)
    
    # Daily authentication attempts - FIXED: Use Django's TruncDate
    daily_auth_attempts = AuthenticationLog.objects.filter(
        timestamp__gte=seven_days_ago
    ).annotate(
        date=TruncDate('timestamp')
    ).values('date').annotate(
        count=Count('id'),
        success_count=Count('id', filter=Q(success=True))
    ).order_by('date')
    
    # Daily slice access attempts - FIXED: Use Django's TruncDate
    daily_slice_attempts = SliceAccessLog.objects.filter(
        timestamp__gte=seven_days_ago
    ).annotate(
        date=TruncDate('timestamp')
    ).values('date').annotate(
        count=Count('id'),
        granted_count=Count('id', filter=Q(access_granted=True))
    ).order_by('date')
    
    # Security level distribution
    security_level_dist = TrustedDevice.objects.values('security_level').annotate(
        count=Count('id')
    ).order_by('security_level')
    
    # Slice performance analytics
    slice_performance = SliceAccessLog.objects.filter(
        access_granted=True,
        bandwidth_used__isnull=False,
        latency__isnull=False
    ).values('slice__name').annotate(
        avg_bandwidth=Avg('bandwidth_used'),
        avg_latency=Avg('latency'),
        access_count=Count('id')
    ).order_by('-access_count')
    
    context = {
        'status_distribution': list(status_distribution),
        'type_distribution': list(type_distribution),
        'auth_success_rate': round(auth_success_rate, 2),
        'recent_registrations': recent_registrations,
        'slice_access_stats': list(slice_access_stats),
        'device_access_patterns': list(device_access_patterns),
        'daily_auth_attempts': list(daily_auth_attempts),
        'daily_slice_attempts': list(daily_slice_attempts),
        'security_level_dist': list(security_level_dist),
        'slice_performance': list(slice_performance),
        'total_attempts': total_attempts,
        'successful_attempts': successful_attempts,
        'failed_attempts': failed_attempts,
    }
    return render(request, 'zero_trust_demo/device_analytics.html', context)

@csrf_exempt
def api_authenticate(request):
    """REST API for device authentication"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            device_id = data.get('device_id', '').strip()
            secret_key = data.get('secret_key', '').strip()
            
            # Get client info
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            try:
                device = TrustedDevice.objects.get(device_id=device_id)
                
                # Create authentication log
                auth_log = AuthenticationLog(
                    device=device,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                if device.status == 'LOCKED':
                    auth_log.success = False
                    auth_log.reason = "Device locked"
                    auth_log.save()
                    
                    return JsonResponse({
                        'status': 'denied',
                        'message': 'Device locked due to security violations',
                        'device_name': device.name,
                        'security_level': device.security_level
                    }, status=403)
                
                if device.status != 'APPROVED':
                    auth_log.success = False
                    auth_log.reason = f"Device status: {device.status}"
                    auth_log.save()
                    
                    return JsonResponse({
                        'status': 'denied',
                        'message': f'Device not approved. Status: {device.get_status_display()}',
                        'device_name': device.name
                    }, status=403)
                
                if device.secret_key == secret_key:
                    # Successful authentication
                    device.last_authentication = timezone.now()
                    device.failed_attempts = 0
                    device.save()
                    
                    auth_log.success = True
                    auth_log.reason = "API authentication successful"
                    auth_log.save()
                    
                    return JsonResponse({
                        'status': 'granted',
                        'message': 'Authentication successful',
                        'device_name': device.name,
                        'security_level': device.security_level,
                        'device_type': device.device_type,
                        'session_timeout': 1800  # 30 minutes in seconds
                    })
                else:
                    # Failed attempt
                    device.failed_attempts += 1
                    if device.failed_attempts >= 3:
                        device.status = 'LOCKED'
                    device.save()
                    
                    auth_log.success = False
                    auth_log.reason = "Invalid secret key"
                    auth_log.save()
                    
                    return JsonResponse({
                        'status': 'denied',
                        'message': 'Invalid credentials',
                        'device_name': device.name,
                        'attempts_remaining': max(0, 3 - device.failed_attempts)
                    }, status=401)
                    
            except TrustedDevice.DoesNotExist:
                # Log unknown device attempt
                auth_log = AuthenticationLog(
                    device=None,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    reason="Unknown device ID"
                )
                auth_log.save()
                
                return JsonResponse({
                    'status': 'denied',
                    'message': 'Device not in trusted registry'
                }, status=404)
                
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON data'
            }, status=400)
    
    return JsonResponse({
        'status': 'error',
        'message': 'Only POST requests allowed'
    }, status=405)

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip