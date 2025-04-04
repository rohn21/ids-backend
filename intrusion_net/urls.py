from django.urls import path
from .views import URLInspectionViewSet

urlpatterns = [
    path('intrusion-net/scan/', URLInspectionViewSet.as_view({'post': 'create'}), name='url-inspection-scan'),
]
