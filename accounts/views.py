from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.views.generic import TemplateView
from rest_framework import generics, permissions, authentication, status, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework_simplejwt.authentication import JWTAuthentication
from dj_rest_auth.registration.views import RegisterView
from allauth.account.utils import send_email_confirmation
from .models import Profile
from .serializers import (
    CustomUserSerializer, UserDetailsSerializer
)
from .permissions import IsOwnerOrReadonly
from django.contrib.auth import get_user_model

User = get_user_model()

class UserCreateAPIView(RegisterView):
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        return user

    def create(self, request, *args, **kwargs):
        # print("Request Data: ", request.data)
        serializer = self.get_serializer(data=request.data)
        # print(type(serializer))
        if not serializer.is_valid():
            print(serializer.errors)

        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        # user = self.perform_create(serializer)
        # send_email_confirmation(request, user)  # when email_verification is required

        headers = self.get_success_headers(serializer.validated_data)

        return Response({"detail": "User registered successfully"}, status=status.HTTP_201_CREATED, headers=headers)

class ProfileDetailAPIView(generics.RetrieveUpdateAPIView):
    queryset = Profile.objects.all()
    serializer_class = UserDetailsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerOrReadonly]

    def get_object(self):
        user = self.request.user
        profile, created = Profile.objects.get_or_create(user=user)
        return profile

# class LogoutView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = (IsAuthenticated,)
#
#     def post(self, request, *args, **kwargs):
#         # if self.request.data.get('all'):
#         #     token: OutstandingToken
#         #     for token in OutstandingToken.objects.filter(user=request.user):
#         #         _, _ = BlacklistedToken.objects.get_or_create(token=token)
#         #     return Response(status=status.HTTP_200_OK)  #need-to-review
#         refresh_token = self.request.data.get('refresh')
#         token = RefreshToken(token=refresh_token)
#         token.blacklist()
#         return Response(status=status.HTTP_205_RESET_CONTENT)
