from django.db import models
from accounts.models import BaseModel
# Create your models here.
INTRUDER_STATUS = (
    ('unsafe', 'Unsafe'),
    ('safe', 'Safe'),
)

class URLInspection(BaseModel):
    url = models.URLField()
    inspection_result = models.JSONField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=INTRUDER_STATUS, default='safe')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'url_inspection'

    def __str__(self):
        return self.url