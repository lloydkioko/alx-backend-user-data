#!/usr/bin/env python3
"""
Module of Session Authentication
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """
    Logins a user if their credentials exist in the database
    """
    user_email = request.form.get('email')
    if not user_email:
        return jsonify({'error': 'email missing'}), 400

    user_pwd = request.form.get('password')
    if not user_pwd:
        return jsonify({'error': 'password missing'}), 400

    users = User.search({'email': user_email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    for user in users:
        if user.is_valid_password(user_pwd):
            from api.v1.app import auth
            session_id = auth.create_session(user.id)
            cookie = getenv('SESSION_NAME')
            response = jsonify(user.to_json())
            response.set_cookie(cookie, session_id)

            return response

    return jsonify({"error": "wrong password"}), 401


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
    """
    Logouts a user
    """
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)

    return jsonify({}), 200
