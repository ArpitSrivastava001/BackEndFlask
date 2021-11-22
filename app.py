import re
import os
import uuid
import bcrypt
import pymongo
from datetime import datetime, timedelta
from flask_cors import CORS
from bson.objectid import ObjectId
from flask_mail import Mail, Message
from flask import Flask, jsonify, request, session
from flask_socketio import SocketIO, emit, join_room
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token



app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app.config['SESSION_TYPE'] = 'filesystem'
app.config["JWT_SECRET_KEY"] = b'LIw:NS\xe5\x05\xb2:\x14\xc1\xd2\n(\x90Tj-\x05\x95\xb8"\xca'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'bequotism@gmail.com'
app.config['MAIL_PASSWORD'] = 'optimisticc'
app.config['MAIL_USE_TLS'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16*1024*1024
mail = Mail(app)
socketio = SocketIO(app ,cors_allowed_origins="*")
jwt = JWTManager(app)
cors = CORS(app)




client = pymongo.MongoClient('mongodb+srv://test:test@chatapp.3gdhj.mongodb.net/myFirstDatabase?retryWrites=true&w=majority')
db = client.get_database('ChatDB')
user = db.get_collection('users')
rooms = db.get_collection('rooms')
room_members = db.get_collection('room_members')
messages = db.get_collection('messages')
e2eroom = db.get_collection('e2eroom')



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS



isSuccess = True 




@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response



@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify(isSuccess=False, message="Token has been expired"), 401




@app.route("/", methods=["GET"])
def get_cross():
    response = jsonify(message="Server is running")
    return response




pattern_email = "[a-zA-Z0-9]+@(espranza)+\.(in)"
pattern_name = '[a-zA-Z][a-zA-Z ]+[a-zA-Z]$'
pattern_password = '^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,15}$'





@app.route("/register", methods=["POST"]) 
def register():
    req_json = request.get_json(force=True)
    email = req_json['email'].lower()
    url = os.path.join(app.config['UPLOAD_FOLDER'], 'default.png')
    if (re.search(pattern_email, email)):
        test = user.find_one({"email": email})
    else:
        return jsonify(message="Only Espranza Employees are allowed!", isSuccess=False), 409
    if test:
        return jsonify(message="User Already Exists", isSuccess=False), 409
    else:
        name = req_json['name'].title()
        password = req_json['password']
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    if ((re.search(pattern_name, name)) and (re.search(pattern_password, password))):
        user_info = dict( 
            email=email,
            name=name,
            password=hashed_pw,
            url=url
        )
        user.insert_one(user_info)
        return jsonify(message="User added successfully", isSuccess=True), 201
    else:
        return jsonify(message="Bad Request Please check your input", isSuccess=False), 409




@app.route("/login", methods=['POST'])
def login():
    if request.is_json:
        email = request.json.get('email').lower()
        password = request.json.get('password')
    else:
        email = request.form.get('email').lower()
        password = request.form.get('password')
    test = user.find_one({"email": email})
    hashed_pw = test['password']
    expires = timedelta(hours=6)
    if (test is not None) and (bcrypt.hashpw(password.encode('utf-8'), hashed_pw)==hashed_pw):
        access_token = create_access_token(email, expires_delta=expires)
        return jsonify(
            email=f"{test['email']}", 
            id=f"{test['_id']}", 
            message="Login Succeeded!", 
            access_token=access_token, 
            isSuccess=True), 201
    else:
        return jsonify(message="Bad Email or Password", isSuccess=False), 401




@app.route("/userinput", methods=["GET"])
@jwt_required()
def dashboard():  
    current_user = get_jwt_identity()
    a = user.find({"email": current_user}, {'password': 0})[0]
    return jsonify(
        isSuccess=True, 
        id=f"{a['_id']}", 
        email=f"{a['email']}",
        name=f"{a['name']}", 
        message=f"Logged in as {current_user}. Welcome to Espranza Chat"), 200



@app.route("/chat", methods=["GET"])
def get_data():
    if request.method == 'GET':
        u1 = request.args.get("u1")
        u2 = request.args.get("u2")
        u1_find = user.find_one({'_id': ObjectId(u1)})
        u2_find = user.find_one({'_id': ObjectId(u2)})
        if u1_find and u2_find:
            room_find1 = e2eroom.find_one({'u1':f"{u1_find['_id']}", 'u2':f"{u2_find['_id']}"})
            room_find2 = e2eroom.find_one({'u1':f"{u2_find['_id']}", 'u2':f"{u1_find['_id']}"})
            if room_find1 or room_find2:
                return jsonify(message="Room already in database", room_id=f"{e2eroom['_id']}")
            else:
                room_create = dict(
                    u1=f"{u1_find['_id']}",
                    u1_email=f"{u1_find['email']}",
                    u2=f"{u2_find['_id']}",
                    u2_email=f"{u2_find['email']}"
                )
                e2eroom.insert_one(room_create)
            return jsonify(message="Room created successfully", room_id=f"{e2eroom['_id']}")
        else:
            return jsonify(message="Cannot perform this action", isSuccess=False)



@app.route("/profile/<id>", methods=["GET", "PATCH"])
@jwt_required()  
def profile(id):
    if request.method == 'GET':
        test = user.find_one({"_id": ObjectId(id)})
        if test:
            return jsonify(
                email=f"{test['email']}", 
                name=f"{test['name']}", 
                id=f"{test['_id']}",
                url=f"{test['url']}", 
                isSuccess=True, 
                password=f"{test['password']}"), 201
        else:
            return jsonify(message="User not found", isSuccess=False), 401
    if request.method == 'PATCH':
        email = request.form.get('email').lower()
        name = request.form.get('name').title()
        url = request.files.get('url')
        if url is not None:
            url.save(os.path.join(app.config['UPLOAD_FOLDER'], url.filename))
        test = user.find_one({"_id": ObjectId(id)})
        if (test) and (re.search(pattern_email, email) or re.search(pattern_name, name) ):
            newResponse = user.update_one(
                {"_id": ObjectId(id)},
                {"$set": {
                    "email": email , 
                    "name": name, 
                    "url": f"{os.path.join(app.config['UPLOAD_FOLDER'])}{url.filename}"}}
            )
            return jsonify(message="User updated successfully", isSuccess=True), 201
        else:
            return jsonify(message="User not found.", isSuccess=False), 401
    else:
        return jsonify(message="Bad Request. Please try again.", isSuccess=False), 400




token = uuid.uuid4().hex
token_name = f'http://192.168.0.109:4200/reset?token={token}'



@app.route('/forgot', methods=['POST'])
def forgot():
    if request.method == 'POST':
        email = request.json.get('email')
        global test_forgot
        test_forgot = user.find_one({"email": email})
        if test_forgot:
            msg = Message()
            msg.subject = "Login System : Password Reset Request"
            msg.sender = 'bequotism@gmail.com'
            msg.body = f'''
            This is an Password request mail for
            User : {test_forgot['email']}
            Click on the link to change the password : {token_name}
            '''
            msg.recipients = [test_forgot['email']]
            mail.send(msg)
            return jsonify(message=f"Password reset link has been sent to your email ID", isSuccess=True), 200
        else:
            return jsonify(message="Bad Request", isSuccess=False), 400





@app.route('/reset', methods=['PATCH'])
def reset():
    if request.method == 'PATCH':
        token = request.args.get('token')
        if token:
            password = request.json.get('password')
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            if test_forgot['email'] and re.search(pattern_password, password):
                new_response = user.find_one_and_update(
                    {"email": test_forgot['email']},
                    {'$set':{"password":hashed_pw}}
                ) 
                return jsonify(message="Password has been successfully changed", isSuccess=True), 201
            else:
                return jsonify(message="Either Token has expired or Pattern for new Password hasn't been followed", isSuccess=False), 401
    else:
        return jsonify(message="Bad Request", isSuccess=False), 400




@app.route('/userlist', methods=['GET'])
@jwt_required()
def get_all():
    if request.method == 'GET':
        current_user = get_jwt_identity()
        cu_data = user.find_one({'email':current_user},{'password':0})
        cu_det = {
            'id':f"{cu_data['_id']}",
            'email':f"{cu_data['email']}",
            'name':f"{cu_data['name']}",
            'url':f"{cu_data['url']}"
        }
        list = []
        for get_all in user.find({},{'password':0}):
            list.append({
                'id':f"{get_all.get('_id')}",
                'name':f"{get_all.get('name')}",
                'email':f"{get_all.get('email')}",
                'url':f"{get_all.get('url')}"
            })
        if cu_det in list:
            list.remove(cu_det)
        return jsonify(list), 200
    else:
        return jsonify(message="Bad Request"), 400



'''
@app.route('/userlist', methods=['GET'])
@jwt_required()
def get_all():
    if request.method == 'GET':
        current_user = get_jwt_identity()
        cu_data = user.find_one({'email':current_user},{'password':0})
        c_id = f"{cu_data['_id']}"
        c_email = cu_data['email']
        c_in_room1 = e2eroom.find_one({'u1': c_id})
        room_id = f"{c_in_room1['_id']}"
        msg_in_r = messages.find({'room' : room_id}).limit(1).sort({'$natural': -1})
        cu_det = {
            'id':f"{cu_data['_id']}",
            'email':f"{cu_data['email']}",
            'name':f"{cu_data['name']}",
            'url':f"{cu_data['url']}",
            'msg': f"{msg_in_r['msg']}"
        }
        list = []
        for get_all in user.find({},{'password':0}):
            list.append({
                'id':f"{get_all.get('_id')}",
                'name':f"{get_all.get('name')}",
                'email':f"{get_all.get('email')}",
                'url':f"{get_all.get('url')}",
                'msg': f"{msg_in_r['msg']}"
            })
        if cu_det in list:
            list.remove(cu_det)
        return jsonify(list), 200
    else:
        return jsonify(message="Bad Request"), 400
'''


@app.route('/recent/<u1>', methods=['GET'])
def get_userlist(u1):
    list1 = []
    list2 = []
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    u1_email = u1_find['email']
    for u1_f in e2eroom.find({'u1' : f"{u1_find['_id']}"}):
        room_id = f"{u1_f['_id']}"
        list1.append(
            f"{room_id}"
        )
    for u2_f in e2eroom.find({'u2' : f"{u1_find['_id']}"}):
        room_id = f"{u2_f['_id']}"
        list1.append(f"{room_id}")
    for u1_in_group in rooms.find({'members' : {'$in' : [f"{u1_email}"]}}):
        room_id = f"{u1_in_group['_id']}"
        list1.append(f"{room_id}")
    for i in list1:
        for e2e_find in e2eroom.find({'_id' : ObjectId(i)}):
            for e2f in messages.find({'room': f"{e2e_find['_id']}"}).sort([("date", -1)]).limit(1):
                if e2e_find['u1'] == f"{u1_find['_id']}":
                    list2.append({
                        'msg' : f"{e2f['msg']}",
                        'id': f"{e2e_find['u2']}",
                        'name': f"{user.find_one({'_id': ObjectId(e2e_find['u2'])})['name']}",
                        'url': f"{user.find_one({'_id': ObjectId(e2e_find['u2'])})['url']}"
                    })
                else:
                    list2.append({
                        'msg' : f"{e2f['msg']}",
                        'id': f"{e2e_find['u1']}",
                        'name': f"{user.find_one({'_id': ObjectId(e2e_find['u1'])})['name']}",
                        'url': f"{user.find_one({'_id': ObjectId(e2e_find['u1'])})['url']}"
                    })
        for r_find in rooms.find({'_id': ObjectId(i)}):
            for r2f in messages.find({'room': f"{r_find['_id']}"}).sort([("date", -1)]).limit(1):
                list2.append({
                    'msg': f"{r2f['msg']}",
                    'id': f"{r_find['_id']}",
                    'name': f"{r_find['room_name']}",
                    'url': f"{r_find['url']}"
                })
    
            # list2.append({
            #     'msg' : '',
            #     'sender' : '',
            #     'room' : f"{e2e_find['_id']}"
            # })
            # else:
            # else:
            #     list2.append({
            #         'msg' : '',
            #         'sender' : '',
            #         'room' : f"{e2f['room']}"
            #     })
        
        # for e2f in messages.find({'room': i, 'msg': ''}).sort([("date", -1)]).limit(1):
        #     list2.append({
        #        'msg' : '',
        #        'sender' : '',
        #        'room' : f"{e2f['room']}" 
        #     })
        
    return jsonify(list2)


@app.route('/contacts/<u1>', methods=['GET'])
def get_contacts(u1):
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    admin_find = user.find_one({'email' : "admin1@espranza.in"})
    admin_details = {
        'id' : f"{admin_find['_id']}",
        'name' : f"{admin_find['name']}",
        'url' : f"{admin_find['url']}"
    }
    u1_details = {
        'id' : f"{u1_find['_id']}",
        'name' : f"{u1_find['name']}",
        'url':f"{u1_find['url']}"
    }
    list = []
    for get_all_users in user.find({}).sort([("name", 1)]):
        list.append({
            'id' : f"{get_all_users['_id']}",
            'name' : f"{get_all_users['name']}",
            'url' : f"{get_all_users['url']}"
        })
    if admin_details in list:
        list.remove(admin_details)
    if u1_details in list:
        list.remove(u1_details)
    return jsonify(list)


    # if u1_find:
    #     for u1_e2e in e2eroom.find({'u1' : f"{u1_find['_id']}"}):
    #         room_id = f"{u1_e2e['_id']}"
    #         msg_find = messages.find_one({'room' : room_id})
    #         list1.append( { 
    #             'room' : room_id,
    #             'msg' : msg_find['msg']
    #          } )
    # for u1_e2e1 in list( e2eroom.find({'u1' : f"{u1_find['_id']}"}, {'u1':0 ,'u2':0, 'u1_email':0, 'u2_email':0}) ):
    #     msg_find = list( messages.find( { 'room' : f"{u1_e2e1['_id']}" }, {'_id':0, 'room':0, 'sender':0, 'name':0, 'date':0, 'url':0} ) )
    #     list1.append( msg_find[::] )
        # for u2_e2e in e2eroom.find({'u2' : f"{u1_find['_id']}"}):
        #     room_id = f"{u2_e2e['_id']}"
        #     list.append( {
        #         'room_id' : room_id
        #     } )
    # return jsonify(f"{list1}")






@app.route('/create_room', methods=['POST'])
@jwt_required()
def create_room():
    if request.method == 'POST':
        request_data = request.get_json(force=True)
        current_user = get_jwt_identity()
        cu_f_in_user = user.find_one({'email':current_user})
        created_by = cu_f_in_user['email']
        room_name = request_data['room_name']
        emails = [email for email in request_data['emails'].split(',')]
        url = os.path.join(app.config['UPLOAD_FOLDER'], 'defaultgroup.png')
        room_info = dict(
            room_name=room_name,
            created_by=created_by,
            members=emails,
            url=url
        )
        rooms.insert_one(room_info)
        return jsonify(messages="Room is created successfully",
        isSuccess=True, room_id=f"{room_info['_id']}", room_members=f"{room_info['members']}")



@app.route('/show-groups', methods=['GET'])
def get_all_rooms():
    list = []
    for get_all in rooms.find({},{'created_by':0, 'members':0}):
        list.append({
            'id' : f"{get_all['_id']}",
            'room_name' : f"{get_all.get('room_name')}",
            'url' : f"{get_all.get('url')}"
        })
    return jsonify(list)


@app.route('/group-members/<id>', methods=['GET'])
def show_members(id):
    group_find = rooms.find_one({'_id' : ObjectId(id)})
    if group_find:
        members = group_find['members']
        return jsonify(members)
    else:
        return jsonify(messages="Invalid Group")



@app.route('/group-room/<room_id>', methods=['GET'])
def get_room_details(room_id):
    room_id_find = rooms.find_one({'_id': ObjectId(room_id)})
    if room_id_find:
        return jsonify(
            room_name=f"{room_id_find['room_name']}",
            members=f"{room_id_find['members']}"
        )


@app.route('/get-room/<u1>/<u2>', methods=['GET'])
def get_room(u1, u2):
    u1_f = e2eroom.find_one({'u1': u1, 'u2': u2}) or e2eroom.find_one({'u1': u2, 'u2': u1})
    if u1_f:
        list= []
        room_id = f"{u1_f['_id']}"
        for get_all in messages.find({'room': room_id}):
            list.append({
                'msg_id':f"{get_all['_id']}",
                'msg':f"{get_all['msg']}",
                'sender':f"{get_all['sender']}",
                'name':f"{get_all['name']}",
                'date':f"{get_all['date']}",
                'url':f"{get_all['url']}"
            })
        return jsonify(list)
    else:
        return jsonify(message="Invalid Request", isSuccess=False)


@app.route('/message_delete/<u1>/<mid>', methods=['DELETE'])
def del_message(u1, mid):
    message_find = messages.find_one({'_id':ObjectId(mid), 'sender':u1})
    if message_find:
        messages.delete_one(message_find)
        return jsonify(message="Message deleted successfully", isSuccess=True)
    else:
        return jsonify(message="Message can't be deleted", isSuccess=False)


@app.route('/check/<u1>/<gid>', methods=['GET'])
def check_member(u1, gid):
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    email = u1_find['email']
    name = u1_find['name']
    u1_g_find = rooms.find_one(
        {'members' : { '$in' : [f"{email}"] },
        '_id' : ObjectId(gid)})
    if u1_g_find:
        group_name = u1_g_find['room_name']
        return jsonify(message=f"{name} is in the room : {group_name}", isSuccess=True)
    else:
        return jsonify(message=f"Sorry this can't be happen!", isSuccess=False)




'''
@app.route('/delete_members/<rid>', methods=['PATCH'])
@jwt_required()
def add_members(rid):
    current_user = get_jwt_identity()
    admin_find = user.find_one({'email' : current_user})
    admin_email = admin_find['email']
    request_data = request.get_json(force=True)
    emails = [email for email in request_data['emails'].split(',')]
    rid_search = rooms.find_one({'_id' : ObjectId(rid), 
    'created_by' : admin_email,
    'members' : {'$in' : emails} 
    })
    # return jsonify(f"{rid_search}")
    if rid_search:
        result = rooms.update_one(
            {'_id' : ObjectId(rid)},
            {'$pull' : { 'members' : { '$in' : [f"{emails}"]}}} )
    return jsonify(f"{result}")
'''


@app.route('/group/<gid>')
def get_chat_group(gid):
    gid_search = rooms.find_one( { '_id' : ObjectId(gid) } )
    if gid_search:
        list = []
        room_id = f"{gid_search['_id']}"
        for get_all in messages.find({'room': room_id}):
            list.append({
                'msg_id':f"{get_all['_id']}",
                'msg':f"{get_all['msg']}",
                'sender':f"{get_all['sender']}",
                'name':f"{get_all['name']}",
                'date':f"{get_all['date']}",
                'url':f"{get_all['url']}"
            })
        return jsonify(list)
    else:
        return jsonify(message="Invalid Request", isSuccess=False)


@socketio.on('connect')
def get_connect():
    print("Client Connected!")

@socketio.on('disconnect')
def get_disconnect():
    print("Client Disconnected")


@socketio.on('join')
def get_join(u1, u2):
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    u2_find = user.find_one({'_id' : ObjectId(u2)})
    if u1_find and u2_find:
        e2e_find = e2eroom.find_one({'u1':f"{u1}", 'u2':f"{u2}"}) or e2eroom.find_one({'u1':f"{u2}", 'u2':f"{u1}"})
        if e2e_find:
            roomf = f"{e2e_find['_id']}"
            join_room(roomf)
            print(f"\n\nJoined Room : {roomf}\n\n")
        else:
            room_create = dict(
                u1=f"{u1_find['_id']}",
                u1_email=f"{u1_find['email']}",
                u2=f"{u2_find['_id']}",
                u2_email=f"{u2_find['email']}"
            )
            e2eroom.insert_one(room_create)
            room_id = f"{room_create['_id']}"
            join_room(room_id)
            print(f"\n\nJoined Room : {room_id}\n\n")
    else:
        print("Invalid Request")


@socketio.on('join_group')
def get_join_group(u1, gid):
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    email = u1_find['email']
    u1_in_g_find = rooms.find_one(
        {'members' : {'$in' : [f"{email}"]},
        '_id' : ObjectId(gid)})
    roomf = f"{u1_in_g_find['_id']}"
    join_room(roomf)
    print(f"\n\nJoined Group : {roomf}\n\n")


@socketio.on('message_group')
def send_message_to_group(msg, u1, gid):
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    u1_email = u1_find['email']
    u1_name = u1_find['name']
    u1_url = u1_find['url']
    u1_gid_find = rooms.find_one({
        'members' : { '$in' : [f"{u1_email}"] },
        '_id' : ObjectId(gid)
    })
    if u1_gid_find:
        room = f"{u1_gid_find['_id']}"
        message_info = dict(
            room=room,
            msg=msg,
            sender=u1,
            name=u1_name,
            date=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            url=u1_url
        )
        emit('new_message', {
            "msg":msg,
            "sender":u1,
            "date":message_info['date'],
            "name":u1_name,
            "url":u1_url
        }, room=room)
        messages.insert_one(message_info)
        print(f"\n\nSend {msg} to {room}\n\n")


@socketio.on('message')
def msg(msg, u1, u2):
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    u1_u2_f = e2eroom.find_one({'u1':f"{u1}", 'u2':f"{u2}"}) or e2eroom.find_one({'u1':f"{u2}", 'u2':f"{u1}"})
    if u1_u2_f:
        room = f"{u1_u2_f['_id']}"
        message_info = dict(
            room=room,
            msg=msg['msg'],
            sender=u1,
            name=f"{u1_find['name']}",
            date=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            url=u1_find['url']  
        )
        messages.insert_one(message_info)
        msg_id = f"{message_info['_id']}" 
        emit('new_message', {
            "msg":msg['msg'], 
            "sender":u1, 
            "date":message_info['date'], 
            "name":u1_find['name'], 
            "url":u1_find['url'],
            "msg_id":msg_id
            },  room=room)
        print(f"\n\nSend {msg} to {room}\n\n")

@socketio.on('new_message')
def new_message(msg):
    emit("new_message", msg)

@socketio.on('user_typing')
def is_typing(u1, u2):
    u1_find = user.find_one({'_id' : ObjectId(u1)})
    u2_find = user.find_one({'_id' : ObjectId(u2)})
    u1_u2_f = e2eroom.find_one({'u1':f"{u1}", 'u2':f"{u2}"}) or e2eroom.find_one({'u1':f"{u2}", 'u2':f"{u1}"})
    if u1_u2_f:
        room = f"{u1_u2_f['_id']}"
        emit('get_typing', {
            'u1': u1,
            'u1_name' : f"{u1_find['name']}",
            'u1_url' : f"{u1_find['url']}",
            'u2': u2
        }, broadcast=True, room=room)

# @socketio.on('typing')
# def is_typing(data):
#     emit('typing', data, broadcast=True)





if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", debug=True, port=9999)