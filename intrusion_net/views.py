from django.db.models import Count
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import URLInspection, FileInspection, URLScan
from .serializers import URLInspectionSerializer, FileInspectionSerializer, URLScanSerializer
from utils.virustotal_api_scan import inspect_url, check_virustotal_uploaded_file, check_virustotal_ip, check_virustotal_url_hash
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from urllib.parse import urlparse
from django.shortcuts import get_object_or_404
import socket, subprocess, nmap

class URLInspectionViewSet(viewsets.ModelViewSet):
    queryset = URLInspection.objects.all()
    serializer_class = URLInspectionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        url = request.data.get('url')

        if not url:
            return Response({'error': 'URL is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            inspection_result = inspect_url(url)
            status_label = 'unsafe' if inspection_result['virustotal_malicious'] else 'safe'

            inspection = URLInspection.objects.create(
                url=url,
                inspection_result=inspection_result,
                status=status_label
            )
            # serializer = URLInspectionSerializer(inspection)
            serializer = self.get_serializer(inspection)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'], url_path='ip')
    def scan_ip(self, request):
        url = request.data.get('url')
        if not url:
            return Response({'error': 'IP address is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            domain = urlparse(url).hostname or url
            ip = socket.gethostbyname(domain)
            ip_info = check_virustotal_ip(ip)
            return Response({'ip_info': ip_info}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'], url_path='hash')
    def scan_url_hash(self, request):
        url = request.data.get('url')
        if not url:
            return Response({'error': 'URL is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            data = check_virustotal_url_hash(url)
            return Response({'url_hash_info': data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileScanViewSet(viewsets.ModelViewSet):
    queryset = FileInspection.objects.all()
    serializer_class = FileInspectionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def create(self, request, *args, **kwargs):
        uploaded_file = request.FILES.get('uploaded_file')

        if not uploaded_file:
            return Response({'error': 'No file uploaded.'}, status=status.HTTP_400_BAD_REQUEST)

        result = check_virustotal_uploaded_file(uploaded_file)
        status_label = result.get('status', 'intruded')

        inspection = FileInspection.objects.create(
            file_name=uploaded_file.name,
            scan_result=result,
            status=status_label
        )

        serializer = self.get_serializer(inspection)
        return Response(serializer.data, status=status.HTTP_200_OK)

class InspectionChartsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Count safe and unsafe scans from URLInspection
        url_counts = URLInspection.objects.values('status').annotate(count=Count('id'))
        file_counts = FileInspection.objects.values('status').annotate(count=Count('id'))

        url_data = {'safe': 0, 'unsafe': 0}
        file_data = {'safe': 0, 'unsafe': 0}

        for item in url_counts:
            url_data[item['status']] = item['count']

        for item in file_counts:
            file_data[item['status']] = item['count']

        # Combined Pie Chart Data
        total_safe = url_data['safe'] + file_data['safe']
        total_unsafe = url_data['unsafe'] + file_data['unsafe']

        pie_chart_data = {
            'labels': ['Safe', 'Unsafe'],
            'series': [total_safe, total_unsafe]
        }

        # Bar Chart Data (URLs vs Files, Safe vs Unsafe)
        bar_chart_data = {
            'categories': ['URLs', 'Files'],
            'safe': [url_data['safe'], file_data['safe']],
            'unsafe': [url_data['unsafe'], file_data['unsafe']]
        }

        return Response({
            'pie_chart': pie_chart_data,
            'bar_chart': bar_chart_data
        })

class   URLScanViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request):
        url = request.data.get("url")
        if not url:
            return Response({"error": "URL is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create a new scan record
            url_scan = URLScan.objects.create(url=url)

            # Initialize and run the scan
            nm = nmap.PortScanner()
            nm.scan(hosts=url, arguments='-sV -Pn')

            scan_data = []
            safe_ports = {"80/tcp", "443/tcp", "22/tcp", "53/tcp", "25/tcp"}

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in sorted(lport):
                        port_info = nm[host][proto][port]
                        port_id = f"{port}/{proto}"
                        service = port_info.get('name', 'unknown')
                        state = port_info.get('state', 'unknown')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        full_service = f"{service} {product} {version}".strip()

                        scan_data.append({
                            "port": port_id,
                            "state": state,
                            "service": full_service
                        })

            # Intrusion logic
            is_intruded = any(
                port["port"] not in safe_ports and port["state"] == "open"
                for port in scan_data
            )

            # Save results
            url_scan.intruder_status = "intruded" if is_intruded else "safe"
            url_scan.port_details = scan_data
            url_scan.save()

            return Response({
                "message": "Scan completed",
                "scan_data": scan_data,
                "intruder_status": url_scan.intruder_status
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # def parse_nmap_output(self, output):
    #     scan_results = []
    #     capture = False
    #
    #     for line in output.splitlines():
    #         if line.strip().startswith("PORT"):
    #             capture = True
    #             continue
    #
    #         if capture and line.strip() and not line.startswith("Nmap done:"):
    #             parts = line.split()
    #             if len(parts) >= 3:
    #                 scan_results.append({
    #                     "port": parts[0],
    #                     "state": parts[1],
    #                     "service": " ".join(parts[2:])
    #                 })
    #     return scan_results

    @action(detail=True, methods=['get'])
    def scan_history(self, request, pk=None):
        url_scan = get_object_or_404(URLScan, pk=pk)
        serializer = URLScanSerializer(url_scan)
        return Response({
            "url": url_scan.url,
            "intruder_status": url_scan.intruder_status,
            "port_details": url_scan.port_details,
            "scan_record": serializer.data
        }, status=status.HTTP_200_OK)
