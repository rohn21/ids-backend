from rest_framework import serializers
from .models import Profile
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

# class UserSerializer(serializers.ModelSerializer):
#     profiles = UserProfileDetailSerializer()
#
#     class Meta:
#         model = User
#         fields = ['id', 'email', 'username', 'mobile_number', 'profiles']
#
#     def update(self, instance, validated_data):
#         profile_data = validated_data.pop('profiles', {})
#         instance = super().update(instance, validated_data)
#
#         profile = instance.profiles
#         profile.profile_pic = profile_data.get('profile_pic', profile.profile_pic)
#         profile.save()
#
#         return instance

    # def update(self, instance, validated_data):
    #     # Update the user fields
    #     profile_data = validated_data.pop('profiles', None)
    #     for attr, value in validated_data.items():
    #         setattr(instance, attr, value)
    #
    #     instance.save()
    #
    #     if profile_data:
    #         profile = instance.profile
    #         for attr, value in profile_data.items():
    #             setattr(profile, attr, value)
    #         profile.save()

        # return instance
#
# class UserUpdateSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(required=False)
#     username = serializers.CharField(required=False)
#     mobile_number = serializers.CharField(required=False)
#
#     class Meta:
#         model = User
#         fields = ['email', 'username', 'mobile_number']
#
#     def update(self, instance, validated_data):
#         for attr, value in validated_data.items():
#             setattr(instance, attr, value)
#         instance.save()
#         return instance
#
# class ProfileUpdateSerializer(serializers.ModelSerializer):
#     profile_pic = serializers.ImageField(required=False, allow_null=True)
#
#     class Meta:
#         model = Profile
#         fields = ['profile_pic']
#
#     def update(self, instance, validated_data):
#         for attr, value in validated_data.items():
#             setattr(instance, attr, value)
#         instance.save()
#         return instance
#
# class UserProfileUpdateSerializer(serializers.Serializer):
#     user = UserUpdateSerializer(required=False)
#     profile = ProfileUpdateSerializer(required=False)
#
#     def update(self, instance, validated_data):
#         user_data = validated_data.pop('user', None)
#         profile_data = validated_data.pop('profile', None)
#
#         if user_data:
#             user_serializer = UserUpdateSerializer(instance.user, data=user_data, partial=True)
#             if user_serializer.is_valid():
#                 instance.user = user_serializer.save()
#
#         if profile_data:
#             profile_serializer = ProfileUpdateSerializer(instance.profile, data=profile_data, partial=True)
#             if profile_serializer.is_valid():
#                 instance.profile = profile_serializer.save()
#
#         return instance

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'mobile_number']
        extra_kwargs = {
            'email': {'read_only': True},
            'mobile_number': {'required': False},
        }

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
