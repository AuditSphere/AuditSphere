from django.db import models
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import User
import uuid

class APIToken(models.Model):
    client = models.CharField(max_length=100, unique=True)
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    is_active = models.BooleanField(default=True)  
    last_activity = models.DateTimeField(null=True, blank=True) 
    whitelisted_ips = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.client} - {self.token}"
    
    def is_ip_whitelisted(self, ip_address):
        if not self.whitelisted_ips:
            return True
        whitelisted_ips = [ip.strip() for ip in self.whitelisted_ips.split(',')]
        return ip_address in whitelisted_ips


class LogEntry(models.Model):
    when = models.DateTimeField()
    who = models.CharField(max_length=200)
    action = models.CharField(max_length=200)
    what = models.CharField(max_length=500, null=True)
    where = models.CharField(max_length=100)
    share_name = models.CharField(max_length=100, null=True)
    object_type = models.CharField(max_length=100)
    host = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    old_path = models.CharField(max_length=500, null=True)
    new_path = models.CharField(max_length=500, null=True)
    old_owner = models.CharField(max_length=500, null=True)
    new_owner = models.CharField(max_length=500, null=True)
    old_acl = models.CharField(max_length=5000, null=True)
    new_acl = models.CharField(max_length=5000, null=True)
    def __str__(self):
        return f"{self.when} - {self.who} - {self.action} - {self.what} - {self.where}"
