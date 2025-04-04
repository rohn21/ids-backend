from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import URLInspection, INTRUDER_STATUS
from .serializers import URLInspectionSerializer
from utils.dns_scan import inspect_url
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

class URLInspectionViewSet(viewsets.ModelViewSet):
    queryset = URLInspection.objects.all()
    serializer_class = URLInspectionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        url = request.data.get('url')
        if not url:
            return Response({'error': 'URL is required.'}, status=status.HTTP_400_BAD_REQUEST)

        inspection_result = inspect_url(url)
        status_label = 'unsafe' if inspection_result['virustotal_malicious'] else 'safe'

        inspection = URLInspection.objects.create(
            url=url,
            inspection_result=inspection_result,
            status=status_label
        )
        serializer = URLInspectionSerializer(inspection)
        return Response(serializer.data, status=status.HTTP_201_CREATED)