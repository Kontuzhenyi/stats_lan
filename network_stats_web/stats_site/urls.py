"""
URL configuration for stats_site project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
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
from django.urls import path
from traffic.views import traffic_list, ip_list, user_traffic_list,user_detail, add_mac, is_mac, user_details, user_day_detail

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', traffic_list, name='traffic_list'),
    path('ips/', ip_list, name='ip_list'),
    path('user-traffic/', user_traffic_list, name='user_traffic'),
    path('user-detail/<str:ip>/<str:mac>/', user_detail, name='user_detail'),
    path('add_mac/', add_mac, name='add_mac'),
    path('is_mac/', is_mac, name='is_mac'),
    path('user/<str:mac>/', user_details, name='user_details'),
    path('user/<str:mac>/<str:date>/', user_day_detail, name='user_day_detail'),
]