from django.db import models
from django.utils import timezone
from django.db import models
import random
import string

def generate_random_id():
    return ''.join(random.choices(string.ascii_lowercase, k=4))

from django.db import models

class VM(models.Model):
    id = models.CharField(max_length=4, default=generate_random_id, primary_key=True, unique=True)
    os = models.CharField(max_length=10)
    cpu = models.IntegerField()
    ram = models.IntegerField()
    rom = models.IntegerField()
    packages = models.CharField(max_length=100)
    total = models.IntegerField()
    user = models.CharField(max_length=100)
    payed = models.BooleanField(default=False) # Add this new field with default value False
    status = models.BooleanField(default=False)
    expiration_date = models.DateTimeField(default=timezone.now)
    creation_date = models.DateTimeField(default=timezone.now)
    fbill = models.IntegerField()
    ip = models.CharField(max_length=15)
    pvc = models.CharField(max_length=100)
    vm_name = models.CharField(max_length=100)
    ssh_key = models.CharField(max_length=100)
    volume_name = models.CharField(max_length=150)

    def __str__(self):
        return self.os
    
    class Meta:
        db_table = 'VM'
        app_label = 'admin_custom'



from django.db import models

class Messages(models.Model):
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'messages'
        app_label = 'admin_custom'