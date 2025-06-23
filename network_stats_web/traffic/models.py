from django.db import models

# class Traffic(models.Model):
#     ip = models.TextField()
#     mac = models.CharField()
#     rx = models.BigIntegerField()
#     tx = models.BigIntegerField()
#     inserted_at = models.DateTimeField()

#     class Meta:
#         managed = False  # Django не управляет этой таблицей
#         db_table = 'traffic_202506'  # или использовать динамику позже

class TrafficBuffer(models.Model):
    ip = models.GenericIPAddressField(protocol='IPv4')
    rx = models.BigIntegerField()
    tx = models.BigIntegerField()

    def __str__(self):
        return f"{self.ip} | RX: {self.rx}, TX: {self.tx}"
    
    class Meta:
        db_table = 'traffic_buffer'
    
class Traffic(models.Model):
    ip = models.GenericIPAddressField(protocol='IPv4')
    mac = models.CharField(max_length=17, null=True, blank=True)
    rx = models.BigIntegerField()
    tx = models.BigIntegerField()
    inserted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip} | {self.mac} | {self.inserted_at}"
    
    class Meta:
        db_table = 'traffic'
        managed = False
    
class MacCache(models.Model):
    ip = models.GenericIPAddressField(protocol='IPv4', unique=True)
    mac = models.CharField(max_length=17, null=True, blank=True)
    updated_at = models.DateTimeField()

    def __str__(self):
        return f"{self.ip} -> {self.mac} (обновлено: {self.updated_at})"
    
    class Meta:
        db_table = 'mac_cache'
        managed = False # Django НЕ будет создавать/удалять эту таблицу

class MacAddress(models.Model):
    mac = models.CharField(max_length=17, unique=True)
    description = models.TextField()

    # def __str__(self):
    #     return f"{self.mac} - {self.description}"
    
    class Meta:
        managed = False  # Django не управляет этой таблицей
        db_table = 'mac_addresses'  # или использовать динамику позже