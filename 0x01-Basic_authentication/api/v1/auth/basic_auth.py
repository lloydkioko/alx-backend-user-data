#!/usr/bin/env python3
"""
API Basic Authentication Module
"""
from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """
    Extends the Auth Class by implementing basic authentication using
    Base64 encoding and decoding
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Returns the Base64 part of the Authorization header
        for a Basic Authentication
        """
        if (not authorization_header or
                not isinstance(authorization_header, str)):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split()[-1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Returns the decoded value of a Base64 string
        base64_authorization_header
        """
        if (not base64_authorization_header or
                not isinstance(base64_authorization_header, str)):
            return None

        try:
            decoded_header = base64.b64decode(base64_authorization_header)
            return decoded_header.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Returns the user email and password from the Base64 decoded value
        """
        if (not decoded_base64_authorization_header or
                not isinstance(decoded_base64_authorization_header, str)):
            return (None, None)

        user_data = tuple(decoded_base64_authorization_header.split(":", 1))

        if len(user_data) != 2:
            return (None, None)

        return user_data

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on his email and password
        """
        if not user_email or not isinstance(user_email, str):
            return None
        if not user_pwd or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Overloads Auth and retrieves the User instance for a request:
        """
        auth_header = self.authorization_header(request)
        b64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(b64_header)
        user_data = self.extract_user_credentials(decoded_header)
        user = self.user_object_from_credentials(user_data[0], user_data[1])

        return user
