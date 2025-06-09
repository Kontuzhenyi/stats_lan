from django.db import models

class Traffic(models.Model):
    ip = models.TextField()
    mac = models.TextField()
    rx = models.BigIntegerField()
    tx = models.BigIntegerField()
    inserted_at = models.DateTimeField()

    class Meta:
        managed = False  # Django не управляет этой таблицей
        db_table = 'traffic_202506'  # или использовать динамику позже