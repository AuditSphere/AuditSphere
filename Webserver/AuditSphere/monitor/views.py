from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import LogEntry, APIToken
from .serializers import LogEntrySerializer
import uuid
import datetime


class LogEntryList(APIView):
    def post(self, request, format=None):
        data = request.data
        if isinstance(data, list):  # Check if incoming data is a list
            serializer = LogEntrySerializer(data=data, many=True)  # Set many=True for batch processing
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Handle single log entry case (optional, based on your requirements)
            serializer = LogEntrySerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@login_required
def manage_clients(request):
    if request.method == 'POST':
        client_name = request.POST.get('client_name')
        whitelisted_ips = request.POST.get('whitelisted_ips', '')
        client, created = APIToken.objects.get_or_create(client=client_name)

        # Update the whitelisted IPs if the client already exists or is newly created
        client.whitelisted_ips = whitelisted_ips
        client.save()

        if created:
            messages.success(request, f'Token generated for {client_name}.')
        else:
            messages.info(request, f'Client {client_name} updated.')

        return redirect('monitor:clients')

    clients = APIToken.objects.all()
    return render(request, 'monitor/manage_clients.html', {'clients': clients})

@login_required
def disable_client(request, token_id):
    api_token = get_object_or_404(APIToken, id=token_id)
    api_token.is_active = False
    api_token.save()
    return redirect('monitor:clients')

@login_required
def enable_client(request, token_id):
    api_token = get_object_or_404(APIToken, id=token_id)
    api_token.is_active = True
    api_token.save()
    return redirect('monitor:clients')

@login_required
def delete_client(request, token_id):
    api_token = get_object_or_404(APIToken, id=token_id)
    api_token.delete()
    return redirect('monitor:clients')

@login_required
def edit_client(request, token_id):
    api_token = get_object_or_404(APIToken, id=token_id)

    if request.method == 'POST':
        client_name = request.POST.get('client_name')
        whitelisted_ips = request.POST.get('whitelisted_ips', '')
        api_token.client = client_name
        api_token.whitelisted_ips = whitelisted_ips
        api_token.save()
        messages.success(request, f'Client {client_name} details updated.')
        return redirect('monitor:clients')

    return render(request, 'monitor/edit_client.html', {'api_token': api_token})
