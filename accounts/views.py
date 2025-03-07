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
from dj_rest_auth.views import LoginView
from allauth.account.utils import send_email_confirmation
from .models import Profile
from .serializers import (
    CustomUserSerializer, UserDetailsSerializer
)
from .permissions import IsAdminOrReadonly, IsOwnerOrReadonly
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
        # user = self.perform_create(serializer)
        # send_email_confirmation(request, user)  # when email_verification is required
        self.perform_create(serializer)

        headers = self.get_success_headers(serializer.validated_data)

        return Response({"detail": "User registered successfully"}, status=status.HTTP_201_CREATED, headers=headers)


class UserLoginView(LoginView):
    def get_response(self):
        user = self.user
        response_data = {
            'user': {
                'username': user.username,
                'email': user.email,
                'role': user.role,
            },
            'access_token': str(self.access_token),
            'refresh_token': str(self.refresh_token),
        }
        return Response(response_data, status=status.HTTP_201_CREATED)


class ProfileDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Profile.objects.all()  # for data with filteration
    serializer_class = UserDetailsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerOrReadonly]

    def get_object(self):
        user = self.request.user
        profile, created = Profile.objects.get_or_create(user=user)
        return profile

    def get_queryset(self):
        return Profile.objects.filter(is_deleted=False)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        user = instance.user
        instance.soft_delete()
        user.soft_delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProfileRestoreAPIView(generics.GenericAPIView):
    queryset = Profile.all_objects.all()  # all_objects used for data without filteration
    serializer_class = UserDetailsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerOrReadonly]

    def get_object(self):
        try:
            profile = Profile.all_objects.get(pk=self.kwargs['pk'])
            return profile
        except Profile.DoesNotExist:
            return None

    def post(self, request, *args, **kwargs):
        instance = self.get_object()

        if instance is None:
            return Response({"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)

        user = instance.user
        if instance.is_deleted:
            instance.restore()
            user.restore()
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response({"detail": "Profile is not deleted."}, status=status.HTTP_400_BAD_REQUEST)

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
