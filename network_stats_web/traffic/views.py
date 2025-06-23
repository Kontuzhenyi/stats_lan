from django.shortcuts import render, redirect, get_object_or_404
from .models import Traffic, MacAddress
from datetime import timedelta, datetime
from django.utils import timezone
from django.db.models import Sum, Min, F, ExpressionWrapper, BigIntegerField, Subquery, OuterRef
from django.db.models.functions import TruncHour
from .forms import MacForm

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
    # Получить все объекты из таблицы Traffic:
    # all_records = MacAddress.objects.all()

    # # Вывести их в консоль
    # for record in all_records:
    #     print(record.mac)
    # test_user = Traffic.objects.values_list('mac', flat=True)
    # print(test_user)
    
    # Подзапрос для получения description по mac
    mac_description = MacAddress.objects.filter(mac=OuterRef('mac')).values('description')[:1]

    query = request.GET.get('q', '').strip()

    # print(query)
    if query:
    # Получаем mac адреса пользователей с описанием, содержащим запрос (регистр можно учесть)
        macs = MacAddress.objects.filter(description__icontains=query).values_list('mac', flat=True)
        # Фильтруем traffic по этим mac
        traffic_qs = Traffic.objects.filter(mac__in=macs)
    else:
        # Если нет поиска, берем всех
        traffic_qs = Traffic.objects.all()

    # test_user = Traffic.objects.values_list('mac', flat=True)
    # print(test_user[0])
    # print(test_user[0]['total_rx'])
    # for row in test_user:
    #     print(row)
    #     break

    user_traffic_row = (
        traffic_qs
        .values('ip', 'mac')
        .annotate(
            total_rx=Sum('rx'),
            total_tx=Sum('tx'),
            username=Subquery(mac_description),
            total_traffic=Sum('rx') + Sum('tx'),
        )
        .order_by('-total_traffic')  # Сортируем сразу в запросе
    )
    # print(user_traffic_row[0])
    for row in user_traffic_row:
        row['total_rx'] = round(row['total_rx'] / (1024 * 1024), 2)
        row['total_tx'] = round(row['total_tx'] / (1024 * 1024), 2)
        row['total_traffic'] = round(row['total_traffic'] / (1024 * 1024), 2)
    # print(user_traffic_row[0])
    # for user in user_traffic_raw:
    #     try:
    #         user['username'] = MacAddress.objects.get(mac=user['mac']).description
    #     except MacAddress.DoesNotExist:
    #         user['username'] = None

    # print(user_traffic_raw)
    # Преобразуем в список с подсчётом total и MB
    # user_traffic = []
    # for entry in user_traffic_raw:
    #     rx = entry['total_rx'] or 0
    #     tx = entry['total_tx'] or 0
    #     total = rx + tx
    #     user_traffic.append({
    #         'ip': entry['ip'],
    #         'mac': entry['mac'],
    #         'username': entry['username'] or 'Unknown',
    #         'total_rx': round(rx / (1024 * 1024), 2),
    #         'total_tx': round(tx / (1024 * 1024), 2),
    #         'total_traffic': round(total / (1024 * 1024), 2),
    #     })

    # # Сортируем по общему трафику
    # user_traffic.sort(key=lambda x: x['total_traffic'], reverse=True)

    return render(request, 'user_traffic.html', {'user_traffic': user_traffic_row})

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

def add_mac(request):
    if request.method == 'POST':
        form = MacForm(request.POST)
        if form.is_valid():
            mac = form.cleaned_data['mac']
            description = form.cleaned_data['description']
            MacAddress.objects.create(mac=mac, description=description)
            return redirect('add_mac')  # Перенаправление на ту же страницу
    else:
        form = MacForm()
    # Получаем все записи для отображения
    mac_addresses = MacAddress.objects.all()
    return render(request, 'add_mac.html', {'form': form, 'mac_addresses': mac_addresses})

# def is_mac(request):
#     context = {'form': IsThereMacForm(), 'exists': None}

#     if request.method == 'POST':
#         form = IsThereMacForm(request.POST)
#         if form.is_valid():
#             mac = form.cleaned_data['mac_address']
#             exists = MacAddress.objects.filter(mac=mac).exists()
#             context.update({
#                 'form': form,
#                 'exists': exists
#             })
#         else:
#             context['form'] = form

#     return render(request, 'is_mac.html', context)

def is_mac(request):
    context = {}
    if request.method == 'POST':
        mac = request.POST.get('mac_address', '')
        exists = MacAddress.objects.filter(mac=mac).exists()
        context = {'exists': exists, 'mac': mac}

    user = Traffic.objects.filter(mac='40:5f:7d:07:87:eb')
    # print(user)
    for row in user:
        print(row.inserted_at)

    return render(request, 'is_mac.html', context)

def user_details(request, mac):
    # Получаем данные пользователя по MAC-адресу
    try:
        user = MacAddress.objects.get(mac=mac)
        username = user.description or 'Без имени'
    except MacAddress.DoesNotExist:
        user = None
        username = 'Без имени'

    # Рассчитываем временные границы
    end_time = timezone.localtime()
    start_time = end_time - timedelta(hours=1)

    mac_value = user.mac if user else mac

    # Получаем данные с минутной детализацией
    traffic_data = Traffic.objects.filter(mac=mac, inserted_at__range=(start_time, end_time)).order_by('inserted_at')
    agg = traffic_data.aggregate( # Результатом будет словарь
        total_rx=Sum('rx'),
        total_tx=Sum('tx')
    )

    total_rx = agg['total_rx'] or 0
    total_tx = agg['total_tx'] or 0

    total = round((total_rx + total_tx) / 1024 / 1024, 2)

    # Получаем день самой ранней записи
    all_traffic_data = Traffic.objects.filter(mac=mac)
    earliest = all_traffic_data.aggregate(earliest_time=Min('inserted_at'))
    earliest['earliest_time'] += timedelta(hours=5)
    # day = earliest['earliest_time'].day
    # days = []
    # days.append(earliest['earliest_time'].day)
    # for row in all_traffic_data:
    #     if row.inserted_at.day not in days:
    #         days.append(row.inserted_at.day)
    # print(days)

    days = Traffic.objects.filter(mac=mac).datetimes('inserted_at', 'day') # Получаем уникальные даты с точностью до дня
    # day_numbers = [dt.day for dt in days]

    context = {
        'user': user,
        'mac': mac,
        'username': username,
        'total': total,
        'active_days': days,
    }
    
    return render(request, 'user_details.html', context)

# def user_day_detail(request, mac, date):
#     date_obj = datetime.strptime(date, "%Y-%m-%d").date()

#     start = datetime.combine(date_obj, datetime.min.time())
#     end = datetime.combine(date_obj, datetime.max.time())

#     traffic = Traffic.objects.filter(
#         mac=mac,
#         inserted_at__range=(start, end)
#     ).order_by('inserted_at')

#     total_rx = sum(row.rx for row in traffic)
#     total_tx = sum(row.tx for row in traffic)
#     total_mb = round((total_rx + total_tx) / 1024 / 1024, 2)

#     return render(request, 'user_day_detail.html', {
#         'mac': mac,
#         'date': date_obj,
#         'total_mb': total_mb,
#         'traffic': traffic,
#     })

from collections import defaultdict
from django.utils.timezone import make_aware
from datetime import datetime, timedelta

def user_day_detail(request, mac, date):
    date_obj = datetime.strptime(date, "%Y-%m-%d").date()

    # Начало и конец дня
    start = make_aware(datetime.combine(date_obj, datetime.min.time())) # 00:00 дня
    end = make_aware(datetime.combine(date_obj, datetime.max.time())) # 23:59 этого же дня

    # Все записи за день
    traffic = Traffic.objects.filter(
        mac=mac,
        inserted_at__range=(start, end)
    ).order_by('inserted_at')

    # Группировка по часам
    hourly_data = defaultdict(lambda: {'rx': 0, 'tx': 0}) # Автоматически создаст значения по умолчанию для каждого ключа. Будет получаться словарь со словарями
    # Каждый ключ это начало часа
    for row in traffic:
        hour = row.inserted_at.replace(minute=0, second=0, microsecond=0)
        hourly_data[hour]['rx'] += row.rx
        hourly_data[hour]['tx'] += row.tx

    # Преобразуем в список с расчётом total
    hourly_stats = []
    for hour, data in sorted(hourly_data.items()):
        # hourly_data.items() получаем ключ и значение 
        # sorted() отсортировываем по времени
        total_mb = round((data['rx'] + data['tx']) / 1024 / 1024, 2)
        hourly_stats.append({
            'hour_start': hour,
            'hour_end': hour + timedelta(hours=1),
            'total_mb': total_mb,
            'rx': round(data['rx'] / 1024 / 1024, 2),
            'tx': round(data['tx'] / 1024 / 1024, 2),
        })

    # Общий трафик за день
    total_rx = sum(row.rx for row in traffic)
    total_tx = sum(row.tx for row in traffic)
    total_mb = round((total_rx + total_tx) / 1024 / 1024, 2)

    return render(request, 'user_day_detail.html', {
        'mac': mac,
        'date': date_obj,
        'total_mb': total_mb,
        'hourly_stats': hourly_stats,
    })
