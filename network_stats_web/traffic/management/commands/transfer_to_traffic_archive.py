from django.utils import timezone
from datetime import timedelta, datetime
from traffic.models import Traffic, TrafficArchive
from django.db.models import Sum
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Переносит данные из таблицы traffic в таблицу traffic_archive'

    def handle(self, *args, **kwargs):
        self.stdout.write("Команда выполняется")
        # Текущая дата
        now = timezone.now()

        # Дата, которую архивируем — ровно 7 дней назад
        archive_date = (now - timedelta(days=7)).date()

        # Начало и конец дня для фильтрации
        # datetime.combine(date, time) соединяет дату и время, создавая объект datetime.
        # Django использует aware datetime, то есть объекты с привязкой к часовому поясу. 
        # Если передать naive datetime (без часового пояса), Django не сможет сравнивать его с полями DateTimeField в БД.
        # timezone.make_aware(naive_datetime) делает время "осознанным", привязывая его к часовому поясу из настроек Django
        day_start = timezone.make_aware(datetime.combine(archive_date, datetime.min.time()))
        day_end = timezone.make_aware(datetime.combine(archive_date, datetime.max.time()))
        print(f"Архивируемый день: {day_start}")

        # Группировка по IP и MAC, исключая некорректные MAC
        aggregated = (
            Traffic.objects
            .filter(inserted_at__gte=day_start, inserted_at__lte=day_end)
            .exclude(mac='00:00:00:00:00:00')
            .values('ip', 'mac')
            .annotate(
                total_rx=Sum('rx'),
                total_tx=Sum('tx')
            )
        )

        # Запись в архив
        TrafficArchive.objects.bulk_create([
            TrafficArchive(
                ip=entry['ip'],
                mac=entry['mac'],
                rx=entry['total_rx'],
                tx=entry['total_tx'],
                day=day_start  # День архивации, тот, что был 7 дней назад
            )
            for entry in aggregated
        ])

        # Удаляем архивируемые записи из основной таблицы
        Traffic.objects.filter(inserted_at__gte=day_start, inserted_at__lte=day_end).delete()
