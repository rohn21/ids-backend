from django.db import models
from accounts.models import BaseModel
# Create your models here.
INTRUDER_STATUS = (
    ('intruded', 'Intruded'),
    ('safe', 'Safe'),
)

class URLScan(BaseModel):
    url = models.URLField(unique=False, help_text="URL to be scanned")
    intruder_status = models.CharField(max_length=10, choices=INTRUDER_STATUS, default='safe', help_text="Status of the URL after scanning")
    port_details = models.JSONField(blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)

    def __str__(self):
        return self.url

class URLInspection(BaseModel):
    url = models.URLField()
    inspection_result = models.JSONField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=INTRUDER_STATUS, default='safe')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'url_inspection'
        # db_table = 'virus_scan'

    def __str__(self):
        return self.url

class FileInspection(BaseModel):
    file_name = models.CharField(max_length=255)
    uploaded_file = models.FileField(upload_to='uploads/', blank=True, null=True)
    scan_result = models.JSONField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=INTRUDER_STATUS, default='safe')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     db_table = 'malware_detection'

    def __str__(self):
        return f"{self.file_name} - {self.status}"