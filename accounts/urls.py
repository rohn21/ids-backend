from django.urls import path, include
from .views import (UserCreateAPIView, UserLoginView,
                    ProfileDetailAPIView, ProfileRestoreAPIView,
                    ContactusAPIView, UserProfileAPIView)
from dj_rest_auth.views import LoginView, LogoutView
from dj_rest_auth.registration.views import (RegisterView,
                                             ConfirmEmailView, ResendEmailVerificationView, VerifyEmailView
                                             )
from dj_rest_auth.views import PasswordResetView, PasswordResetConfirmView

app_name = 'accounts'

urlpatterns = [
    path('login/', UserLoginView.as_view(), name='rest_login'),
    path('logout/', LogoutView.as_view(), name='rest_logout'),
    path('register/', UserCreateAPIView.as_view(), name='rest_register'),
    path('user/profile/', ProfileDetailAPIView.as_view(), name='user_profile'),
    path('profile/', UserProfileAPIView.as_view(), name='profile'),
    path('user/<int:pk>/profile/restore/', ProfileRestoreAPIView.as_view(), name='user_profile_restore'),
    path('user/password/reset/', PasswordResetView.as_view(), name='rest_password_reset'),
    path('user/password/reset/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),

    # contact-us
    path('contact-us/', ContactusAPIView.as_view(), name='contact_us'),
]
