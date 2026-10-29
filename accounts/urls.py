from django.urls import path

from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('2fa/setup/', views.totp_setup, name='totp_setup'),
    path('2fa/verify/', views.totp_verify, name='totp_verify'),
]
