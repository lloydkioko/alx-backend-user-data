#!/usr/bin/env python3
"""
API Session Authentication Database Module
"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from datetime import datetime, timedelta
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """
    Session Authentication Database class
    """
    def create_session(self, user_id=None):
        """
        Creates and stores new instance of UserSession and returns
        the Session ID
        """
        session_id = super().create_session(user_id)
        if not session_id:
            return None

        session_data = {'user_id': user_id, 'session_id': session_id}
        user_session = UserSession(**session_data)
        user_session.save()

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """
        Returns the User ID by requesting UserSession in the database
        based on session_id
        """
        if not session_id:
            return None

        UserSession.load_from_file()

        user_session_list = UserSession.search({'session_id': session_id})
        if not user_session_list:
            return None

        user_session = user_session_list[0]

        expiration_period = user_session.created_at + timedelta(
            seconds=self.session_duration)
        if datetime.now() > expiration_period:
            return None

        return user_session.user_id

    def destroy_session(self, request=None):
        """
        Destroys the UserSession based on the Session ID from
        the request cookie
        """
        if not request:
            return False

        if not self.session_cookie(request):
            return False

        session_id = self.session_cookie(request)
        user_session_list = UserSession.search({'session_id': session_id})
        if not user_session_list:
            return False

        user_session = user_session_list[0]
        del self.__class__.user_id_by_session_id[session_id]
        try:
            user_session.remove()
        except Exception:
            return False

        return True
