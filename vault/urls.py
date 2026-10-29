from django.urls import path

from . import views

app_name = 'vault'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('files/upload/', views.upload, name='upload'),
    path('files/<uuid:file_id>/download/', views.download, name='download'),
    path('files/<uuid:file_id>/delete/', views.delete, name='delete'),
]
