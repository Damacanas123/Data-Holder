from django.shortcuts import render
from .models import *
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.utils import Error

from django.contrib.auth.hashers import make_password
from threading import currentThread
from django.core import serializers
from random import randint
from datetime import *
import json
#authenticate is not a view but a helper function for authentication obviously
#TODO : finish getDataByName and then write test request chain

#error codes
unknownError = -1
noError = 0
noPostRequest = 1
userCantBeAdded = 2
fieldsNotSet = 3
userDNE = 4
dataAlreadyExists = 5
platformDNE = 6
dataDNE = 7
userAlreadyExists = 8
wrongJsonFormat = 9
nameNotSet = 10
paltformNotSet = 11
dataNotSet = 12
#authentication codes
alreadyHaveSessionKey = -1
gotFirstSessionKey = 0
noSuchSessionId = 1
timeStampOld = 2
cantAuthenticate = 3
gotNextSessionKey = 4

production = False

debug = True

@csrf_exempt
def authenticateFirst(request):
    #accepts post request
    #parameters in the header : x : random number
    #client requests access to the database for the first time when he has no valid session key.
    #session key is a bit string for feige fiat shamir protocol
    #This part is for removing the old sessions
    sessions = Session.objects.all()
    threshold = timedelta(minutes = SESSION_LENGTH)
    now = datetime.now(timezone.utc)
    for s in sessions:
        if now - s.timeStamp > threshold:
            s.delete()
            
    json_data ={}
    
    header = request.META
    try:
    # case server 200.000.02.001
        clientIP = request.META['HTTP_X_FORWARDED_FOR']
    except:
    # case localhost ou 127.0.0.1
        clientIP = request.META['REMOTE_ADDR']
        
    try:
        
        Session.objects.get(keyHolderIP = clientIP)
        json_data.update(
        {"authenticationCode":alreadyHaveSessionKey,"infoA":"you already have a session key"}
        )
        returnStr = json.dumps(json_data)
        response = HttpResponse(returnStr,content_type="application/json")
        return response
    except:
        pass
    sessionKey = ""
    for i in range(SESSION_KEY_LENGTH):
        nextBit = randint(0,1)
        sessionKey += str(nextBit)
    json_data.update(
        {"authenticationCode":gotFirstSessionKey,"infoA":"you got your first session key use it to stay authenticated"}
        )
    returnStr = json.dumps(json_data)
    session = Session(x = header['HTTP_X'],sessionKey = sessionKey,keyHolderIP = clientIP)
    session.save()
    response = HttpResponse(returnStr,content_type="application/json")
    response.__setitem__("sessionKey", sessionKey)
    return response


@csrf_exempt
def authenticate(request):
    #parameters in the header : y = random number related to oldX  x = new random number
    json_data = {}
    authenticated = False
    header = request.META
    try:
    # case server 200.000.02.001
        clientIP = request.META['HTTP_X_FORWARDED_FOR']
    except:
    # case localhost ou 127.0.0.1
        clientIP = request.META['REMOTE_ADDR']
    try:
        session = Session.objects.get(keyHolderIP = clientIP)
    except:
        json_data.update(
            {"authenticationCode":noSuchSessionId,"infoA":"no such session id is in database."}
            )
        returnStr = json.dumps(json_data)
        return authenticated,HttpResponse(returnStr,content_type="application/json")
    now = datetime.now(timezone.utc)
    if now - session.timeStamp > timedelta(minutes = SESSION_LENGTH):
        json_data.update(
            {"authenticationCode":timeStampOld,"infoA":"time stamp is old. Make a request to /authenticateFirst/"}
            )
        returnStr = json.dumps(json_data)
        return authenticated,HttpResponse(returnStr,content_type="application/json")
    y = int(header['HTTP_Y'])
    
    sessionKey = session.sessionKey
    xOld = int(session.x)
    publicKeyFile = open("publicKey.txt","r")#first line is n and then v's
    lines = publicKeyFile.readlines()
    n = int(lines[0][:-1])
    xVerification = pow(y,2,n)
    for i in range(SESSION_KEY_LENGTH):
        if sessionKey[i] == '1':
            xVerification = xVerification*int(lines[i+1][:-1])%n
    if debug:
        print("Y : ",y)
        print("Old X : ",xOld)
        print("Computed X : ",xVerification)
    if xVerification != xOld:
        json_data.update(
            {"authenticationCode":cantAuthenticate,"infoA":"You could not authenticate yourself."}
            )
        returnStr = json.dumps(json_data)
        return authenticated,HttpResponse(returnStr,content_type="application/json")
    else:
        sessionKey = ""
        for i in range(SESSION_KEY_LENGTH):
            nextBit = randint(0,1)
            sessionKey += str(nextBit)
        xNew = header['HTTP_X']
        if debug:
            print("New X : ",xNew)
        session.sessionKey = sessionKey
        session.x = xNew
        session.save()
        json_data.update(
            {"authenticationCode":gotNextSessionKey,"infoA":"you got your next session key, stay authenticated"}
            )
        response = HttpResponse(content_type="application/json")
        response.__setitem__("sessionKey", sessionKey)
        authenticated = True
        return authenticated,response,json_data
    

    

    

@csrf_exempt
def createPerson(request):
    #===========================================================================
    # json format 
    # {"data":{
    #     "name":"barkin"
    #     "password":"123456"
    #     }
    #  }
    #===========================================================================
    auth = authenticate(request)
    response = auth[1]
    
    if not auth[0]:
        return response
    else:
        if production:
            form = request.POST 
        else:
            form = json.loads(request.body.decode())
        print(json.dumps(form))
        json_data = auth[2]
        if request.method != 'POST':
            json_data.update(
                {"errorCode":noPostRequest,"info":"Please make a post request"}
                )
            response.write(json.dumps(json_data))
            return response
        if 'data' not in form:
            json_data.update(
                {"errorCode":wrongJsonFormat,"info":"Wrong json format.Put data you send under \"data\""}
                )
            response.write(json.dumps(json_data))
            return response
        data = form['data']
        try:
            Person.objects.get(name = data['name'])
            json_data.update(
                {"errorCode":userAlreadyExists,"info":"user already exists"}
                )
            response.write(json.dumps(json_data))
            return response
        except:
            pass
        try:
            hashedPass = make_password(data['password'])
            person = Person(name=data['name'],password=hashedPass)
            
        except:
            json_data.update(
                {"errorCode":userCantBeAdded,"info":"user couldn't be added"}
                )
            response.write(json.dumps(json_data))
        else:
            person.save()
            json_data.update(
                {"errorCode":noError,"info":"user is added successfully"}
                )
            response.write(json.dumps(json_data))
        return response
    
@csrf_exempt
def addData(request):  
    #===========================================================================
    # request json format for add data  
    # {"data":{
    #     "name":"barkin",
    #     "platform":"facebook",
    #      "data":[  
    #          {  
    #      "key":"kullan\u0131c\u0131 ad\u0131",
    #      "value":"heyoo"
    #      },
    #      {  
    #      "key":"kullan\u0131c\u0131 ad\u0131",
    #      "value":"heyoo"
    #      }
    #     ]
    #   }
    # }
    #===========================================================================
    auth = authenticate(request)
    response = auth[1]
    
    if not auth[0]:
        return response
    else:
        json_data = auth[2]
        if production:
            form = request.POST 
        else:
            form = json.loads(request.body.decode())
        print(json.dumps(form))
        if 'data' not in form:
            json_data.update(
                {"errorCode":wrongJsonFormat,"info":"Wrong json format.Put data you send under \"data\""}
                )
            response.write(json.dumps(json_data))
            return response
        if 'name' not in form['data']:
            json_data.update(
                {"errorCode":nameNotSet,"info":"name is not set"}
                )
            response.write(json.dumps(json_data))
            return response
        if 'platform' not in form['data']:
            json_data.update(
                {"errorCode":platformNotSet,"info":"platform is not set"}
                )
            response.write(json.dumps(json_data))
            return response
        if 'data' not in form['data']:
            json_data.update(
                {"errorCode":dataNotSet,"info":"Data is not set(Key value pairs are not set)."}
                )
            response.write(json.dumps(json_data))
            return response
        data = form['data']
        try:
            name = Person.objects.get(name = data['name'])
        except:
            json_data.update(
                {"errorCode":userDNE,"info":"user does not exist"}
                )
            response.write(json.dumps(json_data))
            return response
        try:
            platform = Platform.objects.get(name = data['platform'])
        except:
            platform = Platform(name = data['platform'])
            platform.save()
        pairs = data['data']
        for i in pairs:
            try:
                currentData = Password_data.objects.get(
                    user = name,
                    platform = platform,
                    key = i['key'],
                    value = i['value']
                    )
            except:
                newData = Password_data(user = name,platform = platform,key = i['key'],value = i['value'])
                newData.save()
        json_data.update(
                {"errorCode":noError,"info":"Saved successfully."}
                )
        response.write(json.dumps(json_data))
        return response
    
#old addData
#===============================================================================
# @csrf_exempt
# def addData(request):
#     auth = authenticate(request)
#     response = auth[1]
#     
#     if not auth[0]:
#         return response
#     else:
#         json_data = auth[2]
#         if production:
#             form = request.POST 
#         else:
#             form = json.loads(request.body.decode())
#         isSet = 'name' in form and 'platform' in form and 'key' in form and 'value' in form
#         helpMessage = "Remember to do this:post body\nname : ------platform : ------key : -------value : -------"
#             
#             
#         if request.method != 'POST':
#             json_data.update(
#                 {"errorCode":noPostRequest,"info":"Please make a post request"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         if not isSet:
#             json_data.update(
#                 {"errorCode":fieldsNotSet,"info":"Some fields are not set"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         try:
#             currentPlatform = Platform.objects.get(name = form['platform'])
#         except:
#             currentPlatform = Platform(name=form['platform'])
#             currentPlatform.save()
#         try:
#             currentPerson = Person.objects.get(name = form['name'])
#         except:
#             json_data.update(
#                 {"errorCode":userDNE,"info":"User does not exist"}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         try:
#             currentData = Password_data.objects.get(
#                 user = currentPerson,
#                 platform = currentPlatform,
#                 key = form['key'],
#                 value = form['value']
#                 )
#             json_data.update(
#                 {"errorCode":dataAlreadyExists,"info":"Data already exists."}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         except:
#             
#             newDataField = Password_data(
#                 user = currentPerson,
#                 platform = currentPlatform,
#                 key = form['key'],
#                 value = form['value']                             
#                 )
#             newDataField.save()
#             json_data.update(
#                 {"errorCode":noError,"info":"Data created."}
#                 )
#             response.write(json.dumps(json_data))
#         return response
#===============================================================================
@csrf_exempt
def updateData(request):
    #===========================================================================
    # json format   
    # {"data":{
    #     "name":"barkin",
    #     "platform":"facebook",
    #      "data":[  
    #          {  
    #      "id":54,
    #      "key":"kullan\u0131c\u0131 ad\u0131",
    #      "value":"heyoo"
    #      },
    #      {  
    #      "id":55,
    #      "key":"kullan\u0131c\u0131 ad\u0131",
    #      "value":"heyoo"
    #      }
    #     ]
    #   }
    # }
    #===========================================================================
    auth = authenticate(request)
    response = auth[1]
    
    if not auth[0]:
        return response
    else:
        json_data = auth[2]
        if production:
            form = request.POST 
        else:
            form = json.loads(request.body.decode())
        if 'data' not in form:
            json_data.update(
                {"errorCode":wrongJsonFormat,"info":"Wrong json format.Put data you send under \"data\""}
                )
            response.write(json.dumps(json_data))
            return response
        if 'name' not in form['data']:
            json_data.update(
                {"errorCode":nameNotSet,"info":"name is not set"}
                )
            response.write(json.dumps(json_data))
            return response
        if 'platform' not in form['data']:
            json_data.update(
                {"errorCode":platformNotSet,"info":"platform is not set"}
                )
            response.write(json.dumps(json_data))
            return response
        if 'data' not in form['data']:
            json_data.update(
                {"errorCode":dataNotSet,"info":"Data is not set(Key value pairs are not set)."}
                )
            response.write(json.dumps(json_data))
            return response
        data = form['data']
        try:
            name = Person.objects.get(name = data['name'])
        except:
            json_data.update(
                {"errorCode":userDNE,"info":"user does not exist"}
                )
            response.write(json.dumps(json_data))
            return response
        try:
            platform = Platform.objects.get(name = data['platform'])
        except:
            json_data.update(
                {"errorCode":platformDNE,"info":"platform does not exist"}
                )
            response.write(json.dumps(json_data))
            return response
        
        password_data = Password_data.objects.filter(user = name,platform = platform)
        triplets = data['data']
        if not triplets:
            
            for i in password_data:
                print(i.key)
                i.delete()
        else:
            for i in password_data:
                print(i.key)
                found = False
                for j in triplets:
                    if str(i.id) == str(j['id']):
                        found = True
                        break
                if not found:
                    print("in delete")
                    i.delete()
                else:
                    print('previous key:', str(i.key),'next key :',str(j['key']))
                    i.key = j['key']
                    i.value = j['value']
                    i.save()
        json_data.update(
                {"errorCode":noError,"info":"successfully updated"}
                )
        response.write(json.dumps(json_data))
        return response        
#old update     
#===============================================================================
# @csrf_exempt
# def updateData(request):
#     auth = authenticate(request)
#     response = auth[1]
#     
#     if not auth[0]:
#         return response
#     else:
#         json_data = auth[2]
#         if production:
#             form = request.POST 
#         else:
#             form = json.loads(request.body.decode())
#         isSet = 'name' in form and 'platform' in form and 'key' in form and 'value' in form
#         helpMessage = "Remember to do this:post body\nname : ------platform : ------key : -------value : -------"
#             
#             
#         if request.method != 'POST':
#             json_data.update(
#                 {"errorCode":noPostRequest,"info":"Please make a post request"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         
#         
#         
#         if not isSet:
#             json_data.update(
#                 {"errorCode":fieldsNotSet,"info":"Some fields are not set"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         
#         
#         try:
#             currentPlatform = Platform.objects.get(name = form['platform'])
#         except:
#             json_data.update(
#                 {"errorCode":platformDNE,"info":"Platform does not exist in database"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         try:
#             currentPerson = Person.objects.get(name = form['name'])
#         except:
#             json_data.update(
#                 {"errorCode":userDNE,"info":"User does not exist in database"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         try:
#             currentData = Password_data.objects.get(
#                 user = currentPerson,
#                 platform = currentPlatform,
#                 key = form['key'],
#                 value = form['value']
#                 )
#         except:
#             json_data.update(
#                 {"errorCode":dataDNE,"info":"User data does not exist.Maybe you should check the fields you send."+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         
#         if 'newPlatform' in form:
#             try:
#                 newPlatform = Platform.objects.get(name = form['newPlatform'])
#             except:
#                 newPlatform = Platform(form['newPlatform'])
#                 newPlatform.save()
#             #currentData.update(platform = newPlatform)
#             currentData.platform = newPlatform
#             currentData.save()
#         if 'newKey' in form:
#             #currentData.update(key = form['newKey'])
#             currentData.key = form['newKey']
#             currentData.save()
#         if 'newValue' in form:
#             #currentData.update(value = form['newValue'])
#             currentData.value = form['newValue']
#             currentData.save() 
#         json_data.update(
#                 {"errorCode":noError,"info":"Successfully updated."+helpMessage}
#                 )
#         response.write(json.dumps(json_data))
#         return response    
#===============================================================================

@csrf_exempt
def deletePlatform(request):
    #===========================================================================
    # json format 
    # {"data":{
    #     "name":"barkin",
    #     "platform":"facebook"
    # }
    #===========================================================================
    auth = authenticate(request)
    response = auth[1]
    
    if not auth[0]:
        return response
    else:
        json_data = auth[2]
        if production:
            form = request.POST 
        else:
            form = json.loads(request.body.decode())
        if 'data' not in form:
            json_data.update(
                {"errorCode":wrongJsonFormat,"info":"Wrong json format.Put data you send under \"data\""}
                )
            response.write(json.dumps(json_data))
            return response
        if 'name' not in form['data']:
            json_data.update(
                {"errorCode":nameNotSet,"info":"name is not set"}
                )
            response.write(json.dumps(json_data))
            return response
        if 'platform' not in form['data']:
            json_data.update(
                {"errorCode":platformNotSet,"info":"platform is not set"}
                )
            response.write(json.dumps(json_data))
            return response
        data = form['data']
        try:
            name = Person.objects.get(name = data['name'])
        except:
            json_data.update(
                {"errorCode":userDNE,"info":"user does not exist"}
                )
            response.write(json.dumps(json_data))
            return response
        try:
            platform = Platform.objects.get(name = data['platform'])
        except:
            json_data.update(
                {"errorCode":platformDNE,"info":"platform does not exist"}
                )
            response.write(json.dumps(json_data))
            return response
        Password_data.objects.filter(platform = platform, user = name).delete()
        json_data.update(
                {"errorCode":noError,"info":"successfully deleted platform from user"}
                )
        response.write(json.dumps(json_data))
        return response

#===============================================================================
# @csrf_exempt
# def deleteData(request):
#     auth = authenticate(request)
#     response = auth[1]
#     
#     if not auth[0]:
#         return response
#     else:
#         json_data = auth[2]
#         if production:
#             form = request.POST 
#         else:
#             form = json.loads(request.body.decode())
#         isSet = 'name' in form and 'platform' in form and 'key' in form and 'value' in form
#         helpMessage = "Remember to do this:post body\nname : ------platform : ------key : -------value : -------"
#             
#             
#         if request.method != 'POST':
#             json_data.update(
#                 {"errorCode":noPostRequest,"info":"Please make a post request"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         
#         
#         
#         if not isSet:
#             json_data.update(
#                 {"errorCode":fieldsNotSet,"info":"Some fields are not set"+helpMessage}
#                 )
#             response.write(json.dumps(json_data))
#             return response
#         
#     
#     try:
#         currentPlatform = Platform.objects.get(name = form['platform'])
#     except:
#         json_data.update(
#             {"errorCode":platformDNE,"info":"Platform does not exist in database"+helpMessage}
#             )
#         response.write(json.dumps(json_data))
#         return response
#     try:
#         currentPerson = Person.objects.get(name = form['name'])
#     except:
#         json_data.update(
#             {"errorCode":userDNE,"info":"User does not exist in database"+helpMessage}
#             )
#         response.write(json.dumps(json_data))
#         return response
#     try:
#         currentData = Password_data.objects.get(
#             user = currentPerson,
#             platform = currentPlatform,
#             key = form['key'],
#             value = form['value']
#             )
#     except:
#         json_data.update(
#             {"errorCode":dataDNE,"info":"User data does not exist.Maybe you should check the fields you send."+helpMessage}
#             )
#         response.write(json.dumps(json_data))
#         return response
#     
#     try:
#         currentData.delete()
#     except:
#         json_data.update(
#             {"errorCode":unkownError,"info":"Could not delete record fatal error."+helpMessage}
#             )
#         response.write(json.dumps(json_data))
#         return response
#     json_data.update(
#         {"errorCode":noError,"info":"Successfully deleted."+helpMessage}
#         )
#     response.write(json.dumps(json_data))
#     return response
#===============================================================================



@csrf_exempt
def getDataByName(request):
    #===========================================================================
    # request
    # json format
    # {'data':{
    #     'name':barkin
    #     }
    #  }
    #===========================================================================
    auth = authenticate(request)
    response = auth[1]
    
    if not auth[0]:
        return response
    else:
        json_data = auth[2]
        if production:
            form = request.POST 
        else:
            form = json.loads(request.body.decode())
        if 'data' not in form:
            json_data.update(
                {"errorCode":wrongJsonFormat,"info":"Wrong json format.Put data you send under \"data\""}
                )
            response.write(json.dumps(json_data))
            return response
        if 'name' not in form['data']:
            json_data.update(
                {"errorCode":nameNotSet,"info":"name is not set"}
                )
            response.write(json.dumps(json_data))
            return response
        data = form['data']
        try:
            currentPerson = Person.objects.get(name = data['name'])
            print("name is : ",data['name'])
        except:
            json_data.update(
                {"errorCode":userDNE,"info":"User does not exist in database"}
                )
            response.write(json.dumps(json_data))
            return response
        
        
        data = Password_data.objects.filter(user_id = data['name']).order_by('platform')
        dataList = []
        #=======================================================================
        #    return format
        #         [  
        #    {  
        #       "platformName":"FACEBOOK",
        #       "platformData":[  
        #          {  
        #             "id":"111",
        #             "key":"Uaername",
        #             "value":"Kimlik"
        #          }
        #       ]
        #    },
        #    {  
        #       "platformName":"GOOGLE",
        #       "platformData":[  
        #          {  
        #             "id":"112",
        #             "key":"Hhh",
        #             "value":"Kkkk"
        #          }
        #       ]
        #    }
        # ]
        #=======================================================================
        try:
            currentPlatform = data[0].platform
            platformData = []
            platformDic = {"platformName":currentPlatform.name,"platformData":platformData}
            
            for i in data:
                if i.platform == currentPlatform:
                    dataDic = {"id":i.id,"key":i.key,"value":i.value}
                    platformData.append(dataDic)
                else:
                    dataList.append(platformDic)
                    currentPlatform = i.platform
                    platformData = []
                    platformDic = {"platformName":currentPlatform.name,"platformData":platformData}
                    dataDic = {"id":i.id,"key":i.key,"value":i.value}
                    platformData.append(dataDic)
            dataList.append(platformDic)
            returnStr = json.dumps(dataList)
                
        except:
            returnStr = "[]"
            
            
            
        json_data.update(
                    {"errorCode":noError,"info":"Successfully returned. You should be seeing the data sorted with respect to platform"}
                    )
        json_data_loaded = json.loads(returnStr)
        temp = {"data":json_data_loaded}
        json_data.update(temp)
        response.write(json.dumps(json_data))
        return response
    
    
    
    
    
    
    
    