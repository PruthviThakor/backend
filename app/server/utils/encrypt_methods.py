import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64decode, b64encode
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from server.utils.exceptions import UnauthorizedException, InternalServerErrorException, InsufficientPermissionException

key = bytes.fromhex(os.environ.get('SECRET_KEY'))
jwt_key = os.environ.get('JWT_TOKEN_KEY')


def encrypt_message(message):
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(iv + encrypted_data).decode()

def decrypt_message(encrypted_message):
    try:
        data = b64decode(encrypted_message)
        iv = data[:16]  # Extract IV from encrypted message
        encrypted_data = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        return decrypted_data.decode()
    except:
        raise UnauthorizedException("Internal server error occured due to invalid Input")

def generate_token(user, reset=False):
    """
    generates a JWT token
    """
    payload  = {
        'phone_number': user["phone_number"],
        'role': user["role"],
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    if reset:
        payload['role'] = 'reset'
    token = jwt.encode(payload, jwt_key, algorithm='HS256')
    return token

def verify_token(token: str):
    """
    This function should validate the token and return the decoded payload if valid,
    or raise an exception if the token is invalid or expired.
    """
    try:
        decoded_token = jwt.decode(token, jwt_key, algorithms=['HS256'])
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise UnauthorizedException("Token has expired")
    except jwt.InvalidTokenError:
        raise UnauthorizedException("Invalid token")

def jwt_token_verification(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):

    if not credentials:
        raise UnauthorizedException("Invalid credentials")

    try:
        token = credentials.credentials
        payload = verify_token(token)

        # Perform additional validation on the payload
        phone_number = payload.get('phone_number')
        role = payload.get('role')
        expiration = payload.get('exp')

        if not phone_number or not role or not expiration:
            raise UnauthorizedException("Invalid token payload")
        if role=='reset':
                raise InsufficientPermissionException("Insufficient privileges, cannot access this endpoint with reset privilage.")        
        current_time = datetime.utcnow().timestamp()
        if expiration < current_time:
            raise UnauthorizedException("Token has expired")

        return payload
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except InsufficientPermissionException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except HTTPException as e:
        raise e
    except Exception as e:
        internal_server = InternalServerErrorException("Internal Server Error")
        return JSONResponse(status_code=internal_server.code, content=internal_server.to_dict())


def jwt_reset_token_verification(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):

    if not credentials:
        raise UnauthorizedException("Invalid credentials")

    try:
        token = credentials.credentials
        payload = verify_token(token)

        # Perform additional validation on the payload
        phone_number = payload.get('phone_number')
        role = payload.get('role')
        expiration = payload.get('exp')

        if not phone_number or not role or not expiration:
            raise UnauthorizedException("Invalid token payload")
        if role!='reset':
                raise InsufficientPermissionException("Insufficient privileges, cannot reset password with current permission.")
        current_time = datetime.utcnow().timestamp()
        if expiration < current_time:
            raise UnauthorizedException("Token has expired")
        return payload
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except InsufficientPermissionException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except HTTPException as e:
        raise e
    except Exception as e:
        internal_server = InternalServerErrorException("Internal Server Error")
        return JSONResponse(status_code=internal_server.code, content=internal_server.to_dict())

def jwt_admin_token_verification(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):

    if not credentials:
        raise UnauthorizedException("Invalid credentials")

    try:
        token = credentials.credentials
        payload = verify_token(token)

        # Perform additional validation on the payload
        phone_number = payload.get('phone_number')
        role = payload.get('role')
        expiration = payload.get('exp')

        if not phone_number or not role or not expiration:
            raise UnauthorizedException("Invalid token payload")

        # Check role
        if role != 'admin':
            raise InsufficientPermissionException("Insufficient privileges")

        current_time = datetime.utcnow().timestamp()
        if expiration < current_time:
            raise UnauthorizedException("Token has expired")

        return payload
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except InsufficientPermissionException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except HTTPException as e:
        raise e
    except Exception:
        internal_server = InternalServerErrorException("Internal Server Error")
        return JSONResponse(status_code=internal_server.code, content=internal_server.to_dict())