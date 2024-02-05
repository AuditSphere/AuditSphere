from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy
from .forms import LoginForm
from .forms import PasswordResetRequestForm, SetNewPasswordForm, LoginForm
from . import views
from .views import log_chart_data  # Import the view


app_name = 'core'

urlpatterns = [
    path('', views.index, name='index'),
    path('log_chart_data/', log_chart_data, name='log_chart_data'),  # Add this line
    path('contact/', views.contact, name='contact'),
    path('login/', auth_views.LoginView.as_view(template_name='core/login.html', authentication_form=LoginForm), name='login'),
    path('logout/', views.user_logout, name='logout'),
    

    # Password reset URL patterns
    path('password_reset/', auth_views.PasswordResetView.as_view(
        template_name='core/password_reset.html',
        email_template_name='core/password_reset_email.html',
        subject_template_name='core/password_reset_subject.txt',
        form_class=PasswordResetRequestForm,
        success_url=reverse_lazy('core:password_reset_done')  # Specify the success_url with namespace here
    ), name='password_reset'),

    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='core/password_reset_done.html'
    ), name='password_reset_done'),

    path('password_reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='core/password_reset_confirm.html',
        form_class=SetNewPasswordForm,
        success_url=reverse_lazy('core:password_reset_complete')  # Specify the success_url with namespace here
    ), name='password_reset_confirm'),

    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='core/password_reset_complete.html'
    ), name='password_reset_complete'),
]