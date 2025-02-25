from django.shortcuts import render
from .models import ContactUs
from rest_framework import generics, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import ContactUsSerializer


class ContactusAPIView(generics.ListCreateAPIView):
    queryset = ContactUs.objects.all()
    serializer_class = ContactUsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]
