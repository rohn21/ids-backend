from django.db import models
from django.core.validators import RegexValidator


class ContactUs(models.Model):
    first_name = models.CharField(max_length=100, verbose_name="First Name")
    last_name = models.CharField(max_length=100, verbose_name="Last Name")
    email = models.EmailField(verbose_name="Email")
    mobile_number = models.CharField(
        max_length=15,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$', 'Enter a valid phone number')],
        null=True, blank=True
    )
    message = models.TextField(blank=True, verbose_name="Message")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'contact_us'

    def __str__(self):
        return self.email
