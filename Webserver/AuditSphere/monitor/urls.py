from django.urls import path
from .views import LogEntryList, manage_clients, delete_client, enable_client, disable_client, edit_client

app_name = 'monitor'

urlpatterns = [
    path('api/log/', LogEntryList.as_view(), name='log-entry-list'),
    path('clients/', manage_clients, name='clients'),
    path('clients/disable/<int:token_id>/', disable_client, name='disable_client'),
    path('clients/enable/<int:token_id>/', enable_client, name='enable_client'),
    path('clients/delete/<int:token_id>/', delete_client, name='delete_client'),
    path('clients/edit/<int:token_id>/', edit_client, name='edit_client'),

]
