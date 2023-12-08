import jwt
import datetime


from django.http import JsonResponse, HttpResponse
from django.contrib.auth import authenticate, login
from django.views.generic.base import TemplateView
from django.contrib.auth.views import LogoutView, LoginView
from django.conf import settings
from django.urls import reverse_lazy
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render





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

    def generate_token(self, user):
        payload = {
            'id': user.id,
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.JWT_EXP_DELTA_SECONDS)
        }
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)    
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
            
            response = HttpResponse(f'Your token: {token}')
            response.set_cookie('token', token, expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.JWT_EXP_DELTA_SECONDS), httponly=True)

            return response
        else:
            return self.form_invalid(form=form)


class UserLogoutView(TitleMixin, LogoutView):
    title = 'Store - Выход'
    success_url = reverse_lazy('index')

    



def protected_resource(request):
    authorization_header = request.COOKIES.get('inputToken')
    user_token = request.COOKIES.get('token')

    if not authorization_header:
        return render(request, 'users/protected_resource.html', {'message': 'No token provided'})

    # Парсим токен из заголовка (пример: "Bearer <токен>")
    # client_token = authorization_header.split()

    # if len(client_token) != 2 or client_token[0].lower() != 'bearer':
    #     return render(request, 'users/protected_resource.html', {'message': 'Invalid Authorization header'})

    # client_token = client_token[1]
    
    try:
        auth_payload = jwt.decode(authorization_header, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_payload = jwt.decode(user_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if user_payload == auth_payload:
            username = user_payload.get('username')
            return render(request, 'users/protected_resource.html', {'username': username})
        return render(request, 'users/protected_resource.html', {'message': 'Invalid token'})
    except jwt.ExpiredSignatureError:
        return render(request, 'users/protected_resource.html', {'message': 'Token has expired'})
    except jwt.InvalidTokenError:
            return render(request, 'users/protected_resource.html', {'message': 'Invalid token'})


def token_input(request):
    return render(request, 'users/token_input.html')

