import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'sqlite:///{os.path.join(BASE_DIR, "instance", "blog.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    LOGIN_ATTEMPTS_LIMIT = 5
    LOGIN_ATTEMPTS_TIMEOUT = 300
    IP_ATTEMPTS_LIMIT = 10
    IP_ATTEMPTS_TIMEOUT = 900
