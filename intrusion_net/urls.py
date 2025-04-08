from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import URLInspectionViewSet, FileScanViewSet, InspectionChartsView, URLScanViewSet

router = DefaultRouter()
router.register(r'url-scan', URLInspectionViewSet, basename='url-inspect')
router.register(r'scan', URLScanViewSet, basename='urlscan')

urlpatterns = [
    # path('url-scan/', URLInspectionViewSet.as_view({'post': 'create'}), name='url_inspection_scan'),
    path('file-scan/', FileScanViewSet.as_view({'post': 'create'}), name='file_scan'),
    path('inspection-charts/', InspectionChartsView.as_view(), name='inspection_charts'),
    path('', include(router.urls)),
    path('scan/<int:pk>/history/', URLScanViewSet.as_view({'get': 'scan_history'}), name='scan-history'),
]
