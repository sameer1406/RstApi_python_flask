from flask import Flask, request, jsonify
import mysql.connector
from flask_bcrypt import Bcrypt
import datetime
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Digiled@360'
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


@app.route('/login', methods=["POST"])
def login():
    posted_data = request.get_json(force=False, silent=False, cache=True)
    # print(posted_data)
    username = posted_data['username']
    password = posted_data['password']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    print(username)
    cnx = mysql.connector.connect(user='sam', password='password', host='localhost', database='flutter_test')
    cur = cnx.cursor()
    query = "select * from test1 where name=%s"
    cur.execute(query, (username,))
    records = cur.fetchall()
    for record in records:
        name = record[0]
        password_DB = record[1]
        print(name)
        # print(hashed_password, "\n", password_DB)
        if bcrypt.check_password_hash(password_DB, password):
            access_token = create_access_token(identity=name)
            return jsonify({"message": "login Successful", "access_token": access_token, "User": name}), 200
            # return jsonmmify({'token': token.decode('UTF-8')}), 201
            # return jsonify({"message": "Login Successfully",
            #                 "name": name,
            #                 "password": password_DB
            #                 }), 200
    else:
        return jsonify({"message": "User Doesn't Exist, Please SignUp"}), 404


@app.route('/protected', methods=["GET"])
@jwt_required
def getuser():
    current_user = get_jwt_identity()
    return jsonify({"message": current_user})


@app.route('/SignUp', methods=["POST"])
def SignUp():
    posted_Data = request.get_json(force=False, silent=False, cache=True)
    # print(posted_Data['username'])
    username = posted_Data['username']
    password = posted_Data['password']
    print(password)
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cnx = mysql.connector.connect(user='sam', password='password', host='localhost', database='flutter_test')
    cur = cnx.cursor()
    ## TO DO ##
    ### condition to check the user is already registered or not ###
    query = "insert into test1(name,password,datetime) values(%s, %s, %s)"
    cur.execute(query, (username, hashed_password, datetime.datetime.now()))
    cnx.commit()
    cnx.close()
    return jsonify({"message": "Successfully stored",
                    "username": username}), 201


if __name__ == "__main__":
    app.run(debug=True)
