from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from accounts.models import CustomUser  # Import your custom User model

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'phone', 'password', 'first_name', 'last_name']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'phone': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def create(self, validated_data):

        # Extract username from email
        email = validated_data.get('email')
        username = email.split('@')[0]  # Get everything before the '@' symbol
        validated_data['username'] = username

        # Hash the password
        validated_data['password'] = make_password(validated_data['password'])

        return super().create(validated_data)


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_value = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)
