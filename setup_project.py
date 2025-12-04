#!/usr/bin/env python
import os
import sys
import django
from django.core.management import execute_from_command_line

def setup_project():
    """Automated project setup script"""
    print("🚀 Setting up 5G Zero-Trust Security System...")
    
    # Setup Django environment
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fiveg_security.settings')
    django.setup()
    
    # Create database tables
    print("📦 Creating database migrations...")
    execute_from_command_line(['manage.py', 'makemigrations', 'zero_trust_demo'])
    
    print("📊 Applying migrations...")
    execute_from_command_line(['manage.py', 'migrate'])
    
    # Import models
    from zero_trust_demo.models import TrustedDevice, NetworkSlice, SliceAccessPolicy
    
    print("📝 Creating sample devices...")
    sample_devices = [
        {
            'name': 'Emergency Ambulance Unit',
            'device_id': 'EMERG-AMB-001',
            'device_type': 'EMERGENCY',
            'security_level': 'MAXIMUM',
            'status': 'APPROVED'
        },
        {
            'name': 'Smart Factory Sensor',
            'device_id': 'IOT-FACT-001',
            'device_type': 'INDUSTRIAL',
            'security_level': 'HIGH',
            'status': 'APPROVED'
        },
        {
            'name': 'Connected Vehicle',
            'device_id': 'VEHICLE-001',
            'device_type': 'VEHICLE',
            'security_level': 'HIGH',
            'status': 'PENDING'
        },
        {
            'name': 'Medical IoT Device',
            'device_id': 'MED-IOT-001',
            'device_type': 'MEDICAL',
            'security_level': 'MAXIMUM',
            'status': 'APPROVED'
        },
        {
            'name': 'City Surveillance Camera',
            'device_id': 'CAM-CITY-001',
            'device_type': 'IOT_SENSOR',
            'security_level': 'HIGH',
            'status': 'APPROVED'
        },
        {
            'name': 'Public Safety Drone',
            'device_id': 'DRONE-PUB-001',
            'device_type': 'EMERGENCY',
            'security_level': 'MAXIMUM',
            'status': 'APPROVED'
        },
        {
            'name': 'Smart Watch - User 001',
            'device_id': 'WATCH-USER-001',
            'device_type': 'SMART_WATCH',
            'security_level': 'MEDIUM',
            'status': 'APPROVED'
        }
    ]
    
    for device_data in sample_devices:
        if not TrustedDevice.objects.filter(device_id=device_data['device_id']).exists():
            device = TrustedDevice(**device_data)
            device.secret_key = device.generate_secret_key()
            device.save()
            print(f"  ✅ Created: {device.name}")
            print(f"     ID: {device.device_id}")
            print(f"     Key: {device.secret_key}")
            print()

    print("🌐 Creating network slices...")
    sample_slices = [
        {
            'name': 'Emergency Services Slice',
            'slice_id': 'SLICE-EMERG-001',
            'slice_type': 'EMERGENCY',
            'priority': 'CRITICAL',
            'max_latency': 10,
            'min_bandwidth': 100,
            'security_level': 'MAXIMUM',
            'is_active': True
        },
        {
            'name': 'Video Streaming Slice',
            'slice_id': 'SLICE-VIDEO-001',
            'slice_type': 'VIDEO',
            'priority': 'HIGH',
            'max_latency': 20,
            'min_bandwidth': 50,
            'security_level': 'HIGH',
            'is_active': True
        },
        {
            'name': 'IoT Devices Slice',
            'slice_id': 'SLICE-IOT-001',
            'slice_type': 'IOT',
            'priority': 'LOW',
            'max_latency': 100,
            'min_bandwidth': 10,
            'security_level': 'MEDIUM',
            'is_active': True
        },
        {
            'name': 'Enterprise Slice',
            'slice_id': 'SLICE-ENT-001',
            'slice_type': 'ENTERPRISE',
            'priority': 'HIGH',
            'max_latency': 30,
            'min_bandwidth': 200,
            'security_level': 'HIGH',
            'is_active': True
        },
        {
            'name': 'Public Safety Slice',
            'slice_id': 'SLICE-PUBLIC-001',
            'slice_type': 'PUBLIC',
            'priority': 'CRITICAL',
            'max_latency': 15,
            'min_bandwidth': 80,
            'security_level': 'MAXIMUM',
            'is_active': True
        },
        {
            'name': 'Industrial IoT Slice',
            'slice_id': 'SLICE-INDUST-001',
            'slice_type': 'INDUSTRIAL',
            'priority': 'MEDIUM',
            'max_latency': 50,
            'min_bandwidth': 20,
            'security_level': 'HIGH',
            'is_active': True
        }
    ]

    for slice_data in sample_slices:
        if not NetworkSlice.objects.filter(slice_id=slice_data['slice_id']).exists():
            slice_obj = NetworkSlice(**slice_data)
            slice_obj.save()
            print(f"  ✅ Created: {slice_obj.name}")
            print(f"     ID: {slice_obj.slice_id}")
            print(f"     Type: {slice_obj.get_slice_type_display()}")
            print(f"     Performance: {slice_obj.min_bandwidth}Mbps, {slice_obj.max_latency}ms")
            print()

    print("🔐 Creating access policies...")
    # Get slices
    emergency_slice = NetworkSlice.objects.get(slice_id='SLICE-EMERG-001')
    video_slice = NetworkSlice.objects.get(slice_id='SLICE-VIDEO-001')
    iot_slice = NetworkSlice.objects.get(slice_id='SLICE-IOT-001')
    enterprise_slice = NetworkSlice.objects.get(slice_id='SLICE-ENT-001')
    public_slice = NetworkSlice.objects.get(slice_id='SLICE-PUBLIC-001')
    industrial_slice = NetworkSlice.objects.get(slice_id='SLICE-INDUST-001')

    policies = [
        {
            'slice': emergency_slice,
            'allowed_device_types': ['EMERGENCY', 'MEDICAL'],
            'required_security_level': 'MAXIMUM',
            'requires_approval': True
        },
        {
            'slice': video_slice,
            'allowed_device_types': ['SMARTPHONE', 'SMART_WATCH'],
            'required_security_level': 'HIGH',
            'requires_approval': False
        },
        {
            'slice': iot_slice,
            'allowed_device_types': ['IOT_SENSOR', 'INDUSTRIAL'],
            'required_security_level': 'MEDIUM',
            'requires_approval': False
        },
        {
            'slice': enterprise_slice,
            'allowed_device_types': ['SMARTPHONE', 'SMART_WATCH', 'VEHICLE'],
            'required_security_level': 'HIGH',
            'requires_approval': True
        },
        {
            'slice': public_slice,
            'allowed_device_types': ['EMERGENCY', 'MEDICAL', 'VEHICLE'],
            'required_security_level': 'MAXIMUM',
            'requires_approval': True
        },
        {
            'slice': industrial_slice,
            'allowed_device_types': ['INDUSTRIAL', 'IOT_SENSOR'],
            'required_security_level': 'HIGH',
            'requires_approval': False
        }
    ]

    for policy_data in policies:
        if not SliceAccessPolicy.objects.filter(slice=policy_data['slice']).exists():
            policy = SliceAccessPolicy(**policy_data)
            policy.save()
            print(f"  ✅ Policy for: {policy.slice.name}")
            print(f"     Allowed: {', '.join(policy.allowed_device_types)}")
            print(f"     Security: {policy.get_required_security_level_display()}")
            print()

    print("\n🎉 Setup complete!")
    print("=" * 60)
    print("🌐 Start the server: python manage.py runserver")
    print("📱 Main Application: http://127.0.0.1:8000/")
    print("🔐 Admin Panel: http://127.0.0.1:8000/admin/")
    print("\n📊 Demo Pages:")
    print("  🔑 Authentication: http://127.0.0.1:8000/demo/auth/")
    print("  📱 Device Management: http://127.0.0.1:8000/demo/manage/")
    print("  🌐 Network Slicing: http://127.0.0.1:8000/demo/slicing/")
    print("  ⚙️ Slice Management: http://127.0.0.1:8000/demo/slices/")
    print("  🛡️ Security Monitor: http://127.0.0.1:8000/demo/monitor/")
    print("  📈 Analytics: http://127.0.0.1:8000/demo/analytics/")
    print("=" * 60)
    
    print("\n🔧 Sample Test Scenarios for Network Slicing:")
    print("  ✅ Emergency Ambulance → Emergency Slice: ACCESS GRANTED")
    print("  ❌ Factory Sensor → Emergency Slice: ACCESS DENIED (wrong device type)")
    print("  ❌ Ambulance → IoT Slice: ACCESS DENIED (security level too high)")
    print("  ✅ Smart Watch → Video Slice: ACCESS GRANTED")
    print("  ✅ Factory Sensor → Industrial Slice: ACCESS GRANTED")
    
    print("\n💡 Quick Start:")
    print("  1. Run: python manage.py runserver")
    print("  2. Visit: http://127.0.0.1:8000/demo/slicing/")
    print("  3. Test different device/slice combinations")
    print("  4. Check Security Monitor for access logs")
    print("=" * 60)

if __name__ == '__main__':
    setup_project()