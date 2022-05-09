from __future__ import absolute_import, unicode_literals
from celery import shared_task
import requests

@shared_task
def add(title, id, duration, url):
    myobj = {"title": title,
    "id": id,
    "duration": duration,
    "url": url
    }
    elasticsearch_url = 'http://127.0.0.1:9200/youtube_data/_doc/' + id
    # elasticsearch_url = 'http://127.0.0.1:9200/' + id + '/_doc/' + id
    re = requests.post(elasticsearch_url, json=myobj)
    return 1