#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
        session.clear()  # Clear the entire session
        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        if not json or 'username' not in json or 'password' not in json:
            return {'message': 'Missing username or password'}, 400
        
        user = User.query.filter_by(username=json['username']).first()
        if user:
            return {'message': 'Username already exists'}, 409
        
        user = User(username=json['username'])
        user.set_password(json['password'])  # Securely set the password
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id  # Save user's ID in the session
        return user.to_dict(), 201

class CheckSession(Resource):
    
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'message': 'Unauthorized'}, 401
        
        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        
        return user.to_dict(), 200

class Login(Resource):
    
    def post(self):
        json = request.get_json()
        if not json or 'username' not in json or 'password' not in json:
            return {'message': 'Missing username or password'}, 400
        
        user = User.query.filter_by(username=json['username']).first()
        if not user or not user.check_password(json['password']):
            return {'message': 'Invalid username or password'}, 401
        
        session['user_id'] = user.id
        return user.to_dict(), 200

class Logout(Resource):
    
    def delete(self):
        session.clear()
        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
