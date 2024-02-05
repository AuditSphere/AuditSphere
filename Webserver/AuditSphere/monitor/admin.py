from django.contrib import admin
from .models import LogEntry, APIToken

admin.site.register(LogEntry)

@admin.register(APIToken)
class APITokenAdmin(admin.ModelAdmin):
    list_display = ('client', 'token', 'is_active', 'last_activity', 'whitelisted_ips')
    list_filter = ('is_active',)  # Filter option
    search_fields = ('client',)  # Search option

