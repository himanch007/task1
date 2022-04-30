from pymongo.write_concern import WriteConcern
from pymodm import MongoModel, fields
from OAuth.settings import DATABASES


class User(MongoModel):
    email = fields.EmailField()
    username = fields.CharField()
    password = fields.CharField()

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'task1-DB'
        final = True


class Desktop_token(MongoModel):
    id = fields.ObjectIdField(primary_key=True)
    access_token = fields.CharField()
    refresh_token = fields.CharField()

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'task1-DB'
        final = True


class Mobile_token(MongoModel):
    id = fields.ObjectIdField(primary_key=True)
    access_token = fields.CharField()
    refresh_token = fields.CharField()

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'task1-DB'
        final = True