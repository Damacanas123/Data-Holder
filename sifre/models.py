from django.db.models import *
SESSION_KEY_LENGTH = 20
SESSION_LENGTH = 20 # in minutes

# Create your models here.
class Person(Model):
    name = CharField(max_length=100,primary_key = True)
    password = TextField()
    
class Platform(Model):
    name = CharField(max_length=100,primary_key = True)
class Password_data(Model):
    user = ForeignKey(Person,on_delete = CASCADE)
    platform = ForeignKey(Platform,on_delete = CASCADE)
    key = TextField()
    value = TextField()
class Session(Model):
    #there will be 20 secret keys for zero knowledge protocol
    x = TextField()
    sessionKey = CharField(max_length = SESSION_KEY_LENGTH)
    keyHolderIP = CharField(max_length = 50)
    timeStamp = DateTimeField(auto_now = True)
    
