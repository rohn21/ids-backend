from rest_framework import serializers
from .models import Profile, ContactUs
from django.contrib.auth import get_user_model

User = get_user_model()


class CustomUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(style={'input_type': 'password'}, source='password2', write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'mobile_number', 'password', 'confirm_password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.pop('password2', None)

        if password and confirm_password is not None:  # Check if both are present
            if password != confirm_password:
                raise serializers.ValidationError(
                    {"status": "error", "message": "Passwords do not match"})
        elif password and confirm_password is None:  # Password is present but confirm_password is missing
            raise serializers.ValidationError(
                {"status": "error", "message": "Confirm Password is required."})
        return attrs

    def create(self, validated_data):
        # validated_data = self.validated_data
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        profile = Profile.objects.create(user=user)

        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)  # Pop password
        validated_data.pop('confirm_password', None)

        if password:
            instance.set_password(password)  # Hash password
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'mobile_number']
        extra_kwargs = {
            'email': {'read_only': True},
            'mobile_number': {'required': False},
        }


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.ReadOnlyField(source="user.email")
    mobile_number = serializers.ReadOnlyField(source="user.mobile_number")
    is_staff = serializers.ReadOnlyField(source="user.is_staff")
    is_active = serializers.ReadOnlyField(source="user.is_active")

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'mobile_number', 'is_staff', 'is_active']


class UserDetailsSerializer(serializers.ModelSerializer):
    user = UserSerializer(required=False)
    is_email_verified = serializers.ReadOnlyField(source="user.is_email_verified")

    class Meta:
        model = Profile
        fields = ['id', 'profile_pic', 'user', 'is_email_verified']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        instance = super().update(instance, validated_data)

        if user_data:
            user = instance.user
            user.mobile_number = user_data.get('mobile_number', user.mobile_number)
            user.username = user_data.get('username', user.username)
            user.save()
        return instance

class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.ReadOnlyField(source='user.username')

    class Meta:
        model = Profile
        fields = ['profile_pic', 'username']


class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = "__all__"