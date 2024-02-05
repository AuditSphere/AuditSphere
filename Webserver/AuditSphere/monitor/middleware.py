from django.http import JsonResponse
from django.utils import timezone
from .models import APIToken

class TokenAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.headers.get('Authorization')
        if token:
            token = token.replace('Token ', '', 1)
            try:
                api_token = APIToken.objects.get(token=token, is_active=True)
                client_ip = self.get_client_ip(request)
                if not api_token.is_ip_whitelisted(client_ip):
                    return JsonResponse({'error': 'IP address not whitelisted'}, status=403)
                api_token.last_activity = timezone.now()
                api_token.save()
            except APIToken.DoesNotExist:
                return JsonResponse({'detail': 'Invalid or inactive token'}, status=401)
            
        return self.get_response(request)

    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip