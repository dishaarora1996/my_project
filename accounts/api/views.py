from django.contrib.auth import authenticate
from django.db import transaction
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token  # Import Token model
from rest_framework.exceptions import APIException, ValidationError

from .serializers import *
from accounts.models import *
from accounts.utils import *

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
            except Exception as e:
                raise APIException({'msg': str(e), 'request_status': 0})

            data = {
                    "username": user.username,
                    "email": user.email,
                    "user_id": user.id,
                    'request_status': 1,
                    "msg": "Successfully registered"

                }
            return Response(data, status=status.HTTP_201_CREATED)

        raise APIException({'msg': serializer.errors, 'request_status': 0})



class LoginAPIView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        # Authenticate the user
        user = authenticate(email=email, password=password)
        if user is None:
            raise APIException({'msg': 'Invalid email or password', 'request_status': 0})

        # Create or get the token for the user
        token, created = Token.objects.get_or_create(user=user)
        data = {
            'token': token.key,
            'username': user.username,
            'user_id': user.id,
            'email': user.email,
            'request_status': 1,
            "msg": "Successfully login"
        }
        return Response(data, status=status.HTTP_200_OK)



class VerifyOTPView(APIView):
    def post(self, request, format=None):
        otp_value = request.data.get('otp_value')
        user_id = request.data.get('user_id')

        now = timezone.now()

        user = CustomUser.objects.filter(pk=user_id).select_for_update().first()
        if not user:
            raise APIException({'msg': 'User not found', 'request_status': 0})

        try:
            with transaction.atomic():
                otp = OTP.objects.select_for_update().get(
                    user_id=user_id,
                    otp_value=otp_value,
                    is_verified=False,
                    expires_at__gte=now
                )

                otp.is_verified = True
                otp.save()

                user.is_verified = True
                user.is_active = True
                user.save()

                # Create a token for the user
                token, created = Token.objects.get_or_create(user=user)

                data = {
                    "username": user.username,
                    "email": user.email,
                    "user_id": user.id,
                    "token": token.key,
                    'request_status': 1,
                    "msg": "Successfully verified"
                }
                return Response(data, status=status.HTTP_200_OK)

        except OTP.DoesNotExist:
            raise APIException({'msg': 'Invalid OTP', 'request_status': 0})

        except Exception as e:
            raise APIException({'msg': str(e), 'request_status': 0})

class ResendOTPView(APIView):
    def post(self, request, format=None):
        user_id = request.data.get('user_id')

        # Check if user exists
        user = CustomUser.objects.filter(pk=user_id).first()
        if not user:
            raise APIException({'msg': 'User not found', 'request_status': 0})

        try:
            with transaction.atomic():
                # Generate a 6-digit OTP
                otp = random.randint(100000, 999999)
                subject = 'Your OTP Code'
                message = f'Hello {user.first_name},\n\nYour OTP code is {otp}.'
                create_otp_send_to_email(user, subject, message)
                data = {
                    "msg": "OTP resent successfully.",
                    "request_status": 1
                }
                return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            raise APIException({"msg": str(e), "request_status": 0})


# OTP required
class ForgotPasswordRequestView(APIView):
    def post(self, request):
        email = request.data['email']

        # Check if user exists
        user = CustomUser.objects.filter(email=email).first()
        if not user:
            raise APIException({'msg': 'User not found', 'request_status': 0})

        try:
            with transaction.atomic():

                # Generate a 6-digit OTP
                otp = random.randint(100000, 999999)
                subject = 'Password Reset Request'
                message = f'Your password reset OTP is {otp}. It is valid for 10 minutes.'
                create_otp_send_to_email(user, subject, message, otp)
                data = {
                        "msg": "Password reset OTP sent to your email",
                        "request_status": 1
                    }
                return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            raise APIException({"msg": str(e), "request_status": 0})


class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_value = serializer.validated_data['otp_value']
            new_password = serializer.validated_data['new_password']

            # Check if user exists
            user = CustomUser.objects.filter(email=email).first()
            if not user:
                raise APIException({'msg': 'User not found', 'request_status': 0})

            now = timezone.now()

            try:
                with transaction.atomic():
                    # Check if OTP is valid
                    otp = OTP.objects.select_for_update().get(
                            user__email=email,
                            otp_value=otp_value,
                            is_verified=False,
                            expires_at__gte=now
                        )

                    # Update the user's password
                    user.password = make_password(new_password)
                    user.save()

                    # Mark the OTP as verified
                    otp.is_verified = True
                    otp.save()

                    return Response({'msg': 'Password reset successfully', 'request_status': 1}, status=status.HTTP_200_OK)

            except OTP.DoesNotExist:
                raise APIException({'msg': 'Invalid OTP', 'request_status': 0})

            except Exception as e:
                raise APIException({'msg': str(e), 'request_status': 0})

        raise APIException({'msg': serializer.errors, 'request_status': 0})


# class ForgotPasswordRequestView(APIView):
#     def post(self, request):
#         email = request.data['email']

#         # Check if user exists
#         user = CustomUser.objects.filter(email=email).first()
#         if not user:
#             raise APIException({'msg': 'User not found', 'request_status': 0})

#         # Generate a token and UID for the user
#         token_generator = PasswordResetTokenGenerator()
#         token = token_generator.make_token(user)
#         uid = urlsafe_base64_encode(force_bytes(user.pk))

#         # Create password reset URL
#         reset_url = request.build_absolute_uri(
#             reverse('reset-password', kwargs={'uidb64': uid, 'token': token})
#         )

#         # Send reset link via email
#         subject = 'Password Reset Request'
#         message = f'Hello {user.first_name},\n\nClick the link below to reset your password:\n{reset_url}'
#         recipient = ['dishaarora1996@gmail.com']    #[user.email]
#         send_mail(subject, message, settings.EMAIL_HOST_USER, recipient)

#         return Response({'msg': 'Password reset link sent to your email', 'request_status': 1}, status=status.HTTP_200_OK)


# class ResetPasswordView(APIView):
#     def post(self, request, uidb64, token):
#         serializer = ResetPasswordSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 # Decode UID and get user
#                 uid = force_str(urlsafe_base64_decode(uidb64))
#                 user = User.objects.get(pk=uid)
#             except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#                 raise APIException({'msg': 'Invalid user', 'request_status': 0})

#             # Validate token
#             token_generator = PasswordResetTokenGenerator()
#             if not token_generator.check_token(user, token):
#                 raise APIException({'msg': 'Invalid or expired token', 'request_status': 0})

#             # Set new password
#             new_password = serializer.validated_data['new_password']
#             user.password = make_password(new_password)
#             user.save()

#             return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)

#         raise APIException({'msg': serializer.errors, 'request_status': 0})









