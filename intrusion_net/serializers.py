from rest_framework import serializers
from .models import URLInspection, FileInspection, URLScan

class URLInspectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLInspection
        fields = '__all__'

class FileInspectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileInspection
        fields = ['file_name', 'status', 'scan_result', 'uploaded_at']

class URLScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLScan
        fields = '__all__'
