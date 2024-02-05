# Import necessary modules
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.core.paginator import Paginator
from django.db.models import Q
from monitor.models import LogEntry
from django.utils.dateparse import parse_datetime
from django.http import HttpResponse
import csv

@login_required
def index(request):
    # Get filter parameters from the request
    search_query = request.GET.get('search')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Get selected actions as a list
    selected_actions = request.GET.getlist('action')
    
    who = request.GET.get('who')
    where = request.GET.get('where')
    share_name = request.GET.get('share_name')
    object_type = request.GET.get('object_type')
    host = request.GET.get('host')
    status = request.GET.get('status')

    # Initialize the query with an empty Q object
    query = Q()

    # Search functionality
    if search_query:
        if ':' in search_query:
            # Advanced search
            field, value = search_query.split(':', 1)
            if field in ['what', 'old_path', 'new_path']:
                kwargs = {f'{field}__icontains': value}
                query &= Q(**kwargs)
        else:
            # Regular search
            query |= Q(what__icontains=search_query) | Q(old_path__icontains=search_query) | Q(new_path__icontains=search_query)

    # Additional filters
    if selected_actions:
        action_query = Q()
        for selected_action in selected_actions:
            action_query |= Q(action=selected_action)
        query &= action_query
        
    if who:
        query &= Q(who__icontains=who)
    if where:
        query &= Q(where__icontains=where)
    if share_name:
        query &= Q(share_name__icontains=share_name)
    if object_type:
        query &= Q(object_type=object_type)
    if host:
        query &= Q(host__icontains=host)
    if status:
        query &= Q(status=status)

    # Date and time range filtering
    if start_date and end_date:
        start = parse_datetime(start_date)
        end = parse_datetime(end_date)
        query &= Q(when__range=(start, end))

    # Apply the filters to the log entries query
    log_entries_query = LogEntry.objects.filter(query).order_by('-when')

    # Advanced sorting functionality
    sort = request.GET.get('sort')
    if sort:
        sort_columns = sort.split(',')  # Split multiple sorting columns
        log_entries_query = log_entries_query.order_by(*sort_columns)  # Use the * operator to unpack the columns

    # Pagination
    entries_per_page = int(request.GET.get('entries_per_page', 15))  # Convert to integer
    paginator = Paginator(log_entries_query, entries_per_page)
    page_number = request.GET.get('page')
    log_entries = paginator.get_page(page_number)

    # CSV Export functionality
    if request.GET.get('export') == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
        writer = csv.writer(response)
        writer.writerow(['When', 'Who', 'Action', 'Where', 'Share Name', 'Object Type', 'Host', 'Status', 'What', 'Old Path', 'New Path'])
        for entry in log_entries:
            writer.writerow([entry.when, entry.who, entry.action, entry.where, entry.share_name, entry.object_type, entry.host, entry.status, entry.what, entry.old_path, entry.new_path])
        return response

    # Render the HTML template with filtered and sorted log entries
    return render(request, 'logs/index.html', {'log_entries': log_entries})
