from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class SignUpSchema(BaseModel):
    firstname: str = Field(...)
    lastname: str = Field(...)
    email: Optional[EmailStr]
    phone_number: str = Field(...)
    password: str = Field(...)
    industry: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "firstname": "John",
                "lastname": "John Doe",
                "email": "jdoe@x.edu.ng",
                "phone_number": "1234567890",
                "password": "xisdbciseiq2dkedkd",
                "industry": "Travel",
            }
        }
    
class UserSchema(SignUpSchema):
    role: Optional[str]

    class Config:
        schema_extra = {
            "example": {
                "firstname": "John",
                "lastname": "John Doe",
                "email": "jdoe@x.edu.ng",
                "phone_number": "1234567890",
                "password": "xisdbciseiq2dkedkd",
                "industry": "Travel",
                "role": "user",
            }
        }
        
class VerificationSchema(BaseModel):
    id: str = Field(...)
    otp: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "id": "1234567890",
                "otp": "3553",
            }
        }

class ResetSchema(BaseModel):
    id: str = Field(...)
    password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "id": "1234567890",
                "password": "cbsjdbsde39dshds",
            }
        }
class UserLoginSchema(BaseModel):
    id: str = Field(...)
    password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "id": "jdoe@x.edu.ng",
                "password": "xisdbciseiq2dkedkd",
            }
        }

class UpdateUserModel(BaseModel):
    industry: Optional[str]
    firstname: Optional[str]
    lastname: Optional[str]
    email: Optional[EmailStr]
    phone_number: Optional[str]
    password: Optional[str]
    role: Optional[str]

    class Config:
        schema_extra = {
            "example": {
                "firstname": "John",
                "lastname": "John Doe",
                "email": "jdoe@x.edu.ng",
                "phone_number": "1234567890",
                "password": "xisdbciseiq2dkedkd",
                "industry": "Travel",
                "role": "user",
                
            }
        }


def ResponseModel(data, message):
    return {
        "data": [data],
        "status": {
        "type": "success",
        "code": 200,
        "message": message,
        }
    }
    
def TokenResponseModel(token, message):
    return {
        "token": token,
        "status": {
        "type": "success",
        "code": 200,
        "message": message,
        }
    }


def ErrorResponseModel(Exception):
    
    return {
        "error": Exception.error,
        "status": {
            "type": "failure",
            "code": Exception.code,
            "message": Exception.message,
        }
    }