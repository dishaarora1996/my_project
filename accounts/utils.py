import random
from django.core.mail import send_mail
from django.conf import settings
from accounts.models import *
from django.utils import timezone
from datetime import timedelta



def create_otp_send_to_email(instance, subject, message, otp):

    # Set the expiration time to 10 minutes from now
    expires_at = timezone.now() + timedelta(minutes=1)

    OTP.objects.create(user=instance, otp_value=otp, expires_at=expires_at)

    # Send OTP via email
    recipient_list = ['dishaarora1996@gmail.com'] # replace later with - [instance.email]

    send_mail(subject, message, settings.EMAIL_HOST_USER, recipient_list)
