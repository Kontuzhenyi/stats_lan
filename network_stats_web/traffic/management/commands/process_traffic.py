import time
from datetime import timedelta, datetime

from django.core.management.base import BaseCommand
from django.utils import timezone
from traffic.models import TrafficBuffer, Traffic, MacCache
import nmap

class Command(BaseCommand):
    help = 'Обработка записей из traffic_buffer и перенос в traffic'

    def get_mac_for_ip(self, ip):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=ip, arguments='-sn', sudo=True)
            if ip in scanner.all_hosts() and scanner[ip].state() == 'up':
                return scanner[ip]['addresses'].get('mac', '00:00:00:00:00:00')
        except Exception as e:
            self.stderr.write(f'Ошибка nmap для {ip}: {e}')
        return '00:00:00:00:00:00'

    def handle(self, *args, **kwargs):
        self.stdout.write("⏳ Запуск обработчика traffic_buffer...")
        while True:
            now = timezone.now()
            buffer_entries = TrafficBuffer.objects.all()
            if buffer_entries.exists(): # Проверяет появились ли новые записи
                self.stdout.write(f"▶ Обработка {buffer_entries.count()} записей...")
                for entry in buffer_entries:
                    ip = entry.ip # Получаем ip

                    mac_entry = MacCache.objects.filter(ip=ip).first() # Пытаемся найти mac-адрес в кэше
                    if mac_entry:
                        age = now - mac_entry.updated_at # Проверяем когда последний раз обновлялся mac
                        if age > timedelta(hours=1): # mac адрес просрочен
                            mac_entry.mac = self.get_mac_for_ip(ip) # Опрашиваем ip с помощью nmap
                            mac_entry.updated_at = now # Обновляем
                            mac_entry.save() # Обновляем
                    else:
                        mac = self.get_mac_for_ip(ip)
                        mac_entry = MacCache.objects.create(ip=ip, mac=mac, updated_at=now)

                    # Запись в таблицу traffic
                    Traffic.objects.create(
                        ip=entry.ip,
                        mac=mac_entry.mac,
                        rx=entry.rx,
                        tx=entry.tx,
                        inserted_at=now
                    )

                    # Удаляем из буфера
                    entry.delete()
                
                self.stdout.write(f"▶ Обработка {buffer_entries.count()} записей закончена")

            time.sleep(17)
