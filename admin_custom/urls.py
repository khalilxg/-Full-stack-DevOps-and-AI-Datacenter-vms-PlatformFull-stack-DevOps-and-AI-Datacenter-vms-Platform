"""admin_custom URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from . import views
from .views import logout_view
from django.urls import path
from .views import change_password
from django.views.generic import TemplateView
from django.urls import path



urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.my_login, name='login'),
    path('hello_world/', views.hello_world_view, name='hello_world'),
    path('registration/', views.registration_view, name='registration'),
    path('logout/', views.logout_view, name='logout'),
    #    path('accounts/', include('django.contrib.auth.urls')),
    # ... other URL patterns ...
    path('password_change/', views.change_password, name='change_password'),
    path('change-password-done/', TemplateView.as_view(template_name='upwd.html'), name='change_password_done'),
    path('my-page/', views.my_view, name='my-page'),

 
    path('createvm/', views.create_vm, name='create_vm'),
    path('managevm/', views.managevm, name='managevm'),
    path('visuals/', views.visuals, name='visuals'),
    
    path('createvm/success/', views.success, name='success'),
    path('createvm/cancel/', views.cancel, name='cancel'),
    
    path('managevm/success/', views.msucceess, name='msuccess'),
    path('managevm/cancel/', views.cancel, name='cancel'),

    path('launch_dashboard/', views.launch_dashboard, name='launch_dashboard'),
    
    path('detect-objects/', views.detect_objects, name='detect-objects'),
    path('get_output_csv/', views.get_output_csv, name='get_output_csv'),
    path('get_output2_csv/', views.get_output2_csv, name='get_output2_csv'),




]



