import jwt
from django.http import JsonResponse
from django.conf import settings

class TokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/protected_resource') and request.method == 'GET':
            token = request.headers.get('Authorization', '').replace('Bearer ', '')

            if not token:
                return JsonResponse({'error': 'No token provided'}, status=401)
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Token has expired'}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({'error': 'Invalid token'}, status=401)

            request.user_id = payload.get('id')
            request.username = payload.get('username')

        return self.get_response(request)
