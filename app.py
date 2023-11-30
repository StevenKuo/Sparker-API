# -*- coding: utf-8 -*-
from flask import Flask, request
from firebase_admin import credentials, initialize_app, db, firestore
import hashlib
import json
import uuid
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
CORS(app)

cred_obj = credentials.Certificate('sparker-265f5-firebase-adminsdk-5kj1y-f6d58c7c79.json')
# default_app = initialize_app(cred_obj, {
# 	'databaseURL':'https://metube-f99bd.firebaseio.com/'
# })
initialize_app(cred_obj)
firestoreDB = firestore.client()
jwt_secret = 'tqbslfs'

@app.route('/')
def hello():
    return f'Hello, Heroku!'

@app.route('/signup', methods=['POST'])
def signup():
    jsonObject = request.json
    if 'email' in jsonObject and 'password' in jsonObject:
        email = jsonObject["email"]
        password = jsonObject["password"]
        md5 = hashlib.md5()
        md5.update(email.encode("utf-8"))
        emailHash = md5.hexdigest()
        # ref = db.reference(f'/user/{hash}')
        # if ref.get() != None:
        #     return {'msg': 'duplicated email'}, 400
        # ref.set({'email': email, 'password': password})
        doc_ref = firestoreDB.collection(u'users').document(emailHash)
        doc_ref.set({
            u'email': email,
            u'password': password,
            u'verified': False
        })
        return 'success', 204
    else:
        return 'bad request!', 400

@app.route('/signin', methods=['GET'])
def signin():
    email = request.args.get('email')
    password = request.args.get('password')
    if email != None and password != None:
        md5 = hashlib.md5()
        md5.update(email.encode("utf-8"))
        emailHash = md5.hexdigest()
        # ref = db.reference(f'/user/{hash}')
        # data = ref.get()
        # if data == None:
        #     return 'Not Found!', 404
        # if data['password'] != password:
        #     return 'Unauthorized!', 401
        doc_ref = firestoreDB.collection(u'users').document(emailHash)
        doc = doc_ref.get()
        if doc.exists:
          data = doc.to_dict()
          if data['password'] != password:
            return 'Unauthorized!', 401
          if data['verified'] != True:
            return 'Unverified!', 401
        else:
          return 'Not Found!', 404
        utc = timezone(timedelta())
        expired = datetime.now(utc) + timedelta(30)
        encoded_jwt = jwt.encode({'email': email, 'expired': expired.isoformat(), 'token': emailHash}, jwt_secret, algorithm='HS256')
        return encoded_jwt, 200
    else:
        return 'Unauthorized!', 401

@app.route('/apps', methods=['GET', 'POST'])
def handleApps():
    headers = request.headers
    try:
        bearer = headers.get('Authorization')
        token = bearer.split()[1]
        decoded_jwt = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        emailHash = decoded_jwt['token']
        expired = datetime.strptime(decoded_jwt['expired'], '%Y-%m-%dT%H:%M:%S.%f%z')
        if datetime.now(timezone(timedelta())) > expired:
          return 'Unauthorized!', 401
        # ref = db.reference(f'/user/{emailHash}')
        # data = ref.get()
        # if data == None:
        #     return 'Unauthorized!', 401
        doc_ref = firestoreDB.collection(u'users').document(emailHash)
        doc = doc_ref.get()
        if doc.exists == False:
          return 'Unauthorized!', 401
    except:
        return 'Unauthorized!', 401

    if request.method == 'GET':
        data = doc.to_dict()
        if 'apps' not in data:
          return 'Not Found!', 404
        appIds = data['apps']
        apps = firestoreDB.collection(u'apps').stream()
        result = []
        for app in apps:
          if app.id in appIds:
            dic = app.to_dict()
            result.append({"id": app.id, "name": dic["name"], "code": dic["code"], "layout": json.loads(dic["layout"])})
        return {"apps": result}, 200

    if request.method == 'POST':
        jsonObject = request.json
        name = jsonObject["name"]
        appid = str(uuid.uuid4())
        aid = str(uuid.uuid4())
        code = str(uuid.uuid4()).upper().replace('-', '')[0:6]
        firestoreDB.collection(u'acls').document(aid).set({'read': [emailHash], 'write': [emailHash]})
        firestoreDB.collection(u'apps').document(appid).set({'aid': aid, 'name': name, 'code': code, "layout": "[]"})
        firestoreDB.collection(u'users').document(emailHash).update({u'apps': firestore.ArrayUnion([appid])})
        # aclRef = db.reference('/acl')
        # appRef = db.reference('/app')
        # aclRef.update({aid: {'read': [hash], 'write': [hash]}})
        # appRef.update({appid: {'aid': aid}})
        # ref.child('apps').update({appid: {'name': name}})
        return 'success', 204

@app.route('/layout', methods=['POST'])
def updateLayout():
  headers = request.headers
  try:
      bearer = headers.get('Authorization')
      token = bearer.split()[1]
      decoded_jwt = jwt.decode(token, jwt_secret, algorithms=["HS256"])
      emailHash = decoded_jwt['token']
      expired = datetime.strptime(decoded_jwt['expired'], '%Y-%m-%dT%H:%M:%S.%f%z')
      if datetime.now(timezone(timedelta())) > expired:
        return 'Unauthorized!', 401
      # ref = db.reference(f'/user/{emailHash}')
      # data = ref.get()
      # if data == None:
      #     return 'Unauthorized!', 401
      doc_ref = firestoreDB.collection(u'users').document(emailHash)
      doc = doc_ref.get()
      if doc.exists == False:
        return 'Unauthorized!', 401
  except:
      return 'Unauthorized!', 401
  jsonObject = request.json
  appId = jsonObject["id"]
  layout = jsonObject["layout"]
  firestoreDB.collection(u'apps').document(appId).update({"layout": layout})
  return 'success', 204

@app.route('/layout/<code>', methods=['GET'])
def queryLayout(code):
  ref = firestoreDB.collection(u'apps')
  query = ref.where(u'code', u'==', code)
  docs = query.stream()
  for doc in docs:
    return doc.to_dict(), 200
  return 'Not Found!', 404

if __name__ == 'main':
    app.run() #啟動伺服器
