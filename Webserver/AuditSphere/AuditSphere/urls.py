from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from core import views
from core.forms import LoginForm
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('admin/login/', auth_views.LoginView.as_view(template_name='core/login.html', authentication_form=LoginForm), name='login'),
    path('admin/', admin.site.urls),
    path('', include('core.urls')),
    path('logs/', include('logs.urls')),
    path('administration/', include('administration.urls')),
    path('monitor/', include('monitor.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
