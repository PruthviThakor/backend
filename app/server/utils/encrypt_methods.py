import os
from cryptography.fernet import Fernet
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from server.utils.exceptions import UnauthorizedException, InternalServerErrorException, InsufficientPermissionException

key = os.environ.get('SECRET_KEY')
jwt_key = os.environ.get('JWT_TOKEN_KEY')

def encrypt_message(message):
    """
    Encrypts a message
    """
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)

    return encrypted_message
    
def decrypt_message(encrypted_message):
    """
    Decrypts an encrypted message
    """
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

def generate_token(user):
    """
    generates a JWT token
    """
    payload  = {
        'email': user["email"],
        'role': user["role"],
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
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
        email = payload.get('email')
        role = payload.get('role')
        expiration = payload.get('exp')

        if not email or not role or not expiration:
            raise UnauthorizedException("Invalid token payload")

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
        print(e)
        internal_server = InternalServerErrorException("Internal Server Error")
        return JSONResponse(status_code=internal_server.code, content=internal_server.to_dict())




def jwt_admin_token_verification(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):

    if not credentials:
        raise UnauthorizedException("Invalid credentials")

    try:
        token = credentials.credentials
        payload = verify_token(token)

        # Perform additional validation on the payload
        email = payload.get('email')
        role = payload.get('role')
        expiration = payload.get('exp')

        if not email or not role or not expiration:
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