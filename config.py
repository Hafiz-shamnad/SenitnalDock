import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')

    database_url = os.getenv("DATABASE_URL", "postgresql://myuser:mypassword@localhost/sentinaldock")
    SQLALCHEMY_DATABASE_URI = database_url

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_PASSWORD = "wupkgzsdboxdcswl"
    MAIL_DEFAULT_SENDER = "connectme.hafiz@gmail.com"

    # Security & API Keys
    SECURITY_PASSWORD_HASH = "pbkdf2_sha512"
    NVD_API_KEY = os.getenv("NVD_API_KEY")


