from rest_framework import serializers
from .models import LogEntry

class LogEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = LogEntry
        fields = [ 'id', 'when', 'who', 'action', 'what', 'where', 'share_name', 'object_type', 'host', 'status', 'old_path', 'new_path', 'old_owner', 'new_owner', 'old_acl', 'new_acl']
