#!/usr/bin/env python3
"""
API Session Authentication Module
"""
from api.v1.auth.auth import Auth
from models.user import User
from uuid import uuid4


class SessionAuth(Auth):
    """
    Extends the Auth Class by implementing session authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a session ID for a user_id
        """
        if not user_id or not isinstance(user_id, str):
            return None

        user_session_id = str(uuid4())
        self.__class__.user_id_by_session_id[user_session_id] = user_id

        return user_session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns a User ID based on a Session ID
        """
        if not session_id or not isinstance(session_id, str):
            return None

        return self.__class__.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Returns a User instance based on a cookie value
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)

        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Deletes the user session / logout
        """
        if not request:
            return False

        if not self.session_cookie(request):
            return False

        session_id = self.session_cookie(request)
        if not self.user_id_for_session_id(session_id):
            return False

        del self.__class__.user_id_by_session_id[session_id]
        return True
