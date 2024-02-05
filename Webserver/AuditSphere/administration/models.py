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

    def __str__(self):
        return f"{self.client} - {self.token}"