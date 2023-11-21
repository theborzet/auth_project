import jwt
import datetime
import requests

from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.views.generic.base import TemplateView
from django.contrib.auth.views import LogoutView, LoginView
from django.conf import settings
from django.urls import reverse_lazy
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST


from common.views import TitleMixin
from users.forms import UserLoginForm


class IndexView(TitleMixin, TemplateView):
    title = 'Store'
    template_name = 'users/index.html'


class UserLoginView(TitleMixin, LoginView):
    title = 'Store - Авторизация'
    template_name = 'users/login.html'
    form_class = UserLoginForm
    success_url = reverse_lazy('index')

    def make_protected_resource_request(self, token):
        url = "http://127.0.0.1:8000/protected_resource/"
        headers = {"Authorization": f"Bearer {token}"}  

        response = requests.get(url, headers=headers)  

        if response.status_code == 200:
            print(response.json())
        else:
            print(f"Error: {response.status_code}")
        return response

    def generate_token(self, user):
        payload = {
            'id': user.id,
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.JWT_EXP_DELTA_SECONDS)
        }
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        self.make_protected_resource_request(token=token)
        return token
    
    def form_invalid(self, form):
        return JsonResponse({'error': 'Invalid credentials'}, status=401)

    def form_valid(self, form):
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        user = authenticate(username=username, password=password)
    
        if user:
            login(self.request, user)
            token = self.generate_token(user)
            return JsonResponse({'Your token' : token})
        else:
            return self.form_invalid(form=form)
        

class UserLogoutView(TitleMixin, LogoutView):
    title = 'Store - Выход'
    success_url = reverse_lazy('index')

@csrf_exempt  # В данном примере для упрощения отключена CSRF-защита
def protected_resource(request):
    token = request.headers.get('Authorization')

    if not token:
        return JsonResponse({'error': 'No token provided'}, status=401)

    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)

    user_id = payload.get('id')
    username = payload.get('username')

    return JsonResponse({'message': f'Hello, {username}! This is a protected resource.'})

