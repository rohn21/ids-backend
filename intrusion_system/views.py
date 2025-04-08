from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import URLInspection, INTRUDER_STATUS
from .serializers import URLInspectionSerializer
from utils.dns_scan import inspect_url, check_virustotal_uploaded_file
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

class URLInspectionViewSet(viewsets.ModelViewSet):
    queryset = URLInspection.objects.all()
    serializer_class = URLInspectionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    # parser_classes = [MultiPartParser, FormParser]

    def create(self, request, *args, **kwargs):
        url = request.data.get('url')
        uploaded_file = request.FILES.get('uploaded_file')

        if not url:
            return Response({'error': 'URL is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            inspection_result = inspect_url(url)

            # Handle uploaded file (if exists)
            if uploaded_file:
                file_scan_result = check_virustotal_uploaded_file(uploaded_file)
                inspection_result['virustotal']['uploaded_file_info'] = file_scan_result

                # rewind file pointer after reading for save
                uploaded_file.seek(0)

            malicious_count = 0
            # status_label = 'unsafe' if inspection_result['virustotal_malicious'] else 'safe'

            try:
                domain_stats = inspection_result['virustotal']['domain_info']['data']['attributes'][
                    'last_analysis_stats']
                url_stats = inspection_result['virustotal']['url_hash_info']['data']['attributes'][
                    'last_analysis_stats']
                malicious_count += domain_stats.get('malicious', 0)
                malicious_count += url_stats.get('malicious', 0)
                if uploaded_file:
                    file_stats = inspection_result['virustotal']['uploaded_file_info']['data']['attributes'][
                        'last_analysis_stats']
                    malicious_count += file_stats.get('malicious', 0)
            except Exception:
                pass

            status_flag = 'safe'
            if malicious_count >= 1:
                status_flag = 'malicious'

            inspection = URLInspection.objects.create(
                url=url,
                inspection_result=inspection_result,
                status=status_flag
            )
            # serializer = URLInspectionSerializer(inspection)
            serializer = self.get_serializer(inspection)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileScanViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def create(self, request, *args, **kwargs):
        uploaded_file = request.FILES.get('uploaded_file')

        if not uploaded_file:
            return Response({'error': 'No file uploaded.'}, status=status.HTTP_400_BAD_REQUEST)

        result = check_virustotal_uploaded_file(uploaded_file)
        return Response({'file_scan_result': result}, status=status.HTTP_200_OK)