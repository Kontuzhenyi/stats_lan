from django.utils import timezone
from datetime import timedelta, datetime
from traffic.models import Traffic, TrafficArchive
from django.db.models import Sum
from django.core.management.base import BaseCommand
from django.db.models.functions import TruncHour, TruncDate

class Command(BaseCommand):

    def handle(self, *args, **kwargs):
        self.stdout.write("Команда выполняется")

        mac = 'c4:74:1e:07:fc:49'

        archive_data = (
            TrafficArchive.objects
            .filter(mac=mac)
            .annotate(day_date=TruncDate('day')) # Выделяем дату без времени
            .order_by('-day_date')
            .values('day_date', 'rx', 'tx')
        )

        print(archive_data[1])

        # for check in archive_data:
        #     print(f"День: {check['day_date']} rx: {check['rx']} tx: {check['tx']}")

