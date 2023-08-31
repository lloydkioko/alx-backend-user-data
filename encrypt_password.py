#!/usr/bin/env python3
"""
Salts and hashes passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Returns a byte string of a salted and hashed password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Returns a boolean that denotes if provided password matches
    the hashed password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
