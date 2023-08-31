#!/usr/bin/env python3
"""
Filtered Logger Module
"""
import logging
from mysql.connector import connection
from os import getenv
import re
from typing import List

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Returns the log message obfuscated
    """
    for field in fields:
        message = re.sub(field + "=.*?" + separator,
                         field + "=" + redaction + separator, message)
    return message


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initiates instance of class
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Filters select values of fields in log records
        """
        return filter_datum(self.fields, self.REDACTION,
                            super(RedactingFormatter, self).format(record),
                            self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Returns a logging.Logger object
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> connection.MySQLConnection:
    """
    Connects to a secure database using environment variables
    """
    config = {
        'user': getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        'password': getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        'host': getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        'database': getenv("PERSONAL_DATA_DB_NAME")
    }

    connector = connection.MySQLConnection(**config)
    return connector


def main() -> None:
    """
    Opens a database connection and retrieves all rows from the users table
    and formats as per the logger implemented
    """
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users;")
    logger = get_logger()

    for row in cursor:
        fields = f"name={row[0]}; email={row[1]}; phone={row[2]}; "\
            f"ssn={row[3]}; password={row[4]}; ip={row[5]}; "\
            f"last_login={row[6]}; user_agent={row[7]};"

        logger.info(fields)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
