from django.shortcuts import render
from .models import Traffic
from datetime import timedelta
from django.db.models import Sum, F, ExpressionWrapper, BigIntegerField
from django.db.models.functions import TruncHour

def traffic_list(request):
    data = Traffic.objects.all().order_by('-inserted_at')[:50] # Берем только последние 100 записей

    traffic_data = []
    for row in data:
        row.inserted_at += timedelta(hours=5)
        traffic_data.append(row)
        
    return render(request, 'list.html', {'traffic_data': traffic_data}) # Передаем их в list.html

def ip_list(request):
    ip_addresses = Traffic.objects.values_list('ip', flat=True).distinct().order_by('ip')
    ip_count = ip_addresses.count()

    mac_addresses = Traffic.objects.values_list('mac', flat=True).distinct().order_by('mac')
    mac_count = mac_addresses.count()

    return render(request, 'ip_list.html', {
        'ip_addresses': ip_addresses,
        'ip_count': ip_count,
        'mac_addresses': mac_addresses,
        'mac_count': mac_count
        })

def user_traffic_list(request):
    user_traffic_raw = (
        Traffic.objects
        .values('ip', 'mac')
        .annotate(
            total_rx=Sum('rx'),
            total_tx=Sum('tx'),
        )
    )

    # Преобразуем в список с подсчётом total и MB
    user_traffic = []
    for entry in user_traffic_raw:
        rx = entry['total_rx'] or 0
        tx = entry['total_tx'] or 0
        total = rx + tx
        user_traffic.append({
            'ip': entry['ip'],
            'mac': entry['mac'],
            'total_rx': round(rx / (1024 * 1024), 2),
            'total_tx': round(tx / (1024 * 1024), 2),
            'total_traffic': round(total / (1024 * 1024), 2),
        })

    # Сортируем по общему трафику
    user_traffic.sort(key=lambda x: x['total_traffic'], reverse=True)

    return render(request, 'user_traffic.html', {'user_traffic': user_traffic})

def user_detail(request):
    ip = request.GET.get('ip')
    mac = request.GET.get('mac')
    
    # Группировка трафика по часу
    traffic_stats = (
        Traffic.objects
        .filter(ip=ip, mac=mac)
        .annotate(period=TruncHour('inserted_at'))
        .values('period')
        .annotate(
            total_rx=Sum('rx'),
            total_tx=Sum('tx'),
            total=Sum('rx') + Sum('tx')
        )
        .order_by('period')
    )

    # Конвертируем байты в мегабайты (примерно)
    for stat in traffic_stats:
        stat['total_rx'] = stat['total_rx'] / (1024 * 1024)
        stat['total_tx'] = stat['total_tx'] / (1024 * 1024)
        stat['total'] = stat['total'] / (1024 * 1024)

    return render(request, 'user_detail.html', {'traffic_stats': traffic_stats, 'ip': ip, 'mac': mac})