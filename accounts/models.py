from django.db import models
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, password2, **extra_fields):
        if not email:
            raise ValueError(_("Email must be set!!!"))

        if password != password2:
            raise ValueError("Passwords don't match!!!")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, username, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_("superuser must have is_staff=True"))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_("superuser must have is_superuser=True"))
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)  # Add other fields
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(unique=True, max_length=200)
    email = models.EmailField(
        verbose_name='Email',
        max_length=254,
        unique=True,
    )
    mobile_number = models.CharField(
        max_length=15,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$', 'Enter a valid phone number')],
        unique=True,
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        db_table = 'user'

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    # @property
    # def is_admin(self):
    #     "Is the user an admin member?"
    #     return self.is_admin

    def __str__(self):
        return self.email


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profiles')
    profile_pic = models.ImageField(upload_to='profile_pics/', blank=True, null=True)

    class Meta:
        db_table = 'user_profile'

    def __str__(self):
        return self.user.username