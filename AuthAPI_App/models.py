from enum import unique
from pymongo.write_concern import WriteConcern

from pymodm import MongoModel, fields

from OAuth.settings import DATABASES

class User(MongoModel):
    email = fields.EmailField(primary_key=True)
    username = fields.CharField()
    password = fields.CharField()

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'task1-DB'