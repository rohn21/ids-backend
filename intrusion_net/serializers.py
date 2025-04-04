from rest_framework import serializers
from .models import URLInspection

class URLInspectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLInspection
        fields = '__all__'