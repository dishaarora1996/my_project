
from django.urls import path, include
from .api.views import *
from .views import *

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),

    # otp required
    # path('forgot-password/', ForgotPasswordRequestView.as_view(), name='forgot-password-request'),
    # path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),

    # without otp
    path('forgot-password/', ForgotPasswordRequestView.as_view(), name='forgot-password'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordView.as_view(), name='reset-password'),
]