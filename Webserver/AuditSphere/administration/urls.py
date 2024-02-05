from django.urls import path
from . import views 
from django.urls import path, include

app_name = 'administration'

urlpatterns = [
   path('users/', views.list_users, name='users'),
    path('users/disable/<int:user_id>/', views.disable_user, name='disable_user'),
    path('users/enable/<int:user_id>/', views.enable_user, name='enable_user'),
    path('users/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/edit/<int:user_id>/', views.edit_user, name='edit_user'),
]
