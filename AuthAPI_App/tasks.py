from __future__ import absolute_import, unicode_literals
from celery import shared_task
import requests
from OAuth import settings

@shared_task
def add(data_to_be_inserted):
    elasticsearch_url = settings.ELASTICSEARCH_URL
    elasticsearch_index = settings.ELASTICSEARCH_INDEXES['youtube_data_index']
    request_url = elasticsearch_url + elasticsearch_index + '_doc/'
    for data in data_to_be_inserted:
        re = requests.post(request_url, json=data)
    return 1