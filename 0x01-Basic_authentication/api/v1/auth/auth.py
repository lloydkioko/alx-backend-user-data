#!/usr/bin/env python3
"""
API Authentication Module
"""
from flask import request
import re
from typing import List, TypeVar


class Auth:
    """
    API Authentication Class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Returns True if the path is not in excluded_paths,
        thus requires authentication
        """
        if (not path or not excluded_paths):
            return True

        path = path + '/' if not path.endswith('/') else path
        for ex_path in excluded_paths:
            match = re.match(ex_path + "([*]?|(/)?)", path)
            if match:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Validates all requests to secure the API
        """
        if request is None or 'Authorization' not in request.headers:
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns None
        """
        return None
