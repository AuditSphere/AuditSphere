from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import logout, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Count
from django.http import JsonResponse
from monitor.models import LogEntry
from django.db.models.functions import TruncHour
from operator import itemgetter




def user_logout(request):
    logout(request)
    return redirect('core:index')

def contact(request):
    return render(request, 'core/contact.html')

@login_required
def get_log_data(request):
    end_date = timezone.now()
    start_date = end_date - timezone.timedelta(days=7)  # Last 7 days

    logs = LogEntry.objects.filter(
    when__range=[start_date, end_date],
    action__in=['Renamed', 'Moved', 'Created', 'Accessed', 'Removed', 'Owner Changed']
    ).annotate(hour=TruncHour('when')).values('hour', 'action', 'who').annotate(count=Count('id')).order_by('hour')


    # Organizing data for line chart
    line_data = {}
    for log in logs:
        hour = log['hour'].strftime('%Y-%m-%d %H:%M:%S')
        if hour not in line_data:
            line_data[hour] = {'Renamed': 0, 'Moved': 0, 'Created': 0, 'Accessed': 0, 'Removed': 0, 'Owner Changed': 0}
        line_data[hour][log['action']] += log['count']

    bar_data = {}
    for log in logs:
        who = log['who']
        if who not in bar_data:
            bar_data[who] = {'total': 0, 'actions': {'Renamed': 0, 'Moved': 0, 'Created': 0, 'Accessed': 0, 'Removed': 0, 'Owner Changed': 0}}
        bar_data[who]['total'] += log['count']
        bar_data[who]['actions'][log['action']] += log['count']

    # Sort the actions based on frequency for each user
    for user_data in bar_data.values():
        user_data['actions'] = dict(sorted(user_data['actions'].items(), key=itemgetter(1), reverse=True))

    return line_data, bar_data


@login_required
def index(request):
    line_chart_data, bar_chart_data = get_log_data(request)
    return render(request, 'core/index.html', {'chart_data': line_chart_data, 'bar_chart_data': bar_chart_data})

@login_required
def log_chart_data(request):
    data = get_log_data(request)
    return JsonResponse(data)