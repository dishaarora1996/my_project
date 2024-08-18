from .models import CustomUser
from django.db.models.signals import post_save
from django.dispatch import receiver
from accounts.utils import create_otp_send_to_email

@receiver(post_save, sender=CustomUser)
def send_otp_to_email(sender, instance, created, **kwargs):
    if created:
        try:
            with transaction.atomic():
                # Generate a 6-digit OTP
                otp = random.randint(100000, 999999)
                subject = 'Your OTP Code'
                message = f'Hello {instance.first_name},\n\nYour OTP code is {otp}.'
                create_otp_send_to_email(instance, subject, message, otp)
        except Exception as e:
            raise APIException({'msg': str(e), 'request_status': 0})



