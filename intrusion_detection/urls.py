from django.urls import path, include
from .views import ContactusAPIView

app_name = 'intrusion-detection'

urlpatterns = [
    path('contact-us/', ContactusAPIView.as_view(), name='contact_us'),
]