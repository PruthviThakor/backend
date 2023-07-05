from fastapi import FastAPI, Body
from fastapi.responses import JSONResponse
from server.routes.users import router
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timedelta
from server.utils.consts import OTP_EXPIRATION_MINUTES
from server.utils.email_methods import verify_otp, generate_otp, send_otp_email, send_otp_sms, verify_signup_otp
from server.utils.exceptions import UnauthorizedException,InternalServerErrorException, NotFoundException, DuplicateEntryException
from server.database import (
    add_user,
    retrieve_query,
    retrieve_user,
    update_user,
    delete_user,
)
from server.utils.utils import identify_contact_info

from server.models.users import (
    ResponseModel,
    UserLoginSchema,
    VerificationSchema,
    TokenResponseModel,
    SignUpSchema
)
from server.utils import encrypt_methods

app = FastAPI()
app.include_router(router, tags=["User"], prefix="/api/user")

@app.get("/api", tags=["Root"])
async def read_root():
    return {"message": "Welcome to this fantastic app!"}

@app.post("/api/signup", tags=["SignUp"])
async def sign_up(user: SignUpSchema = Body(...)):
    try:
        user = jsonable_encoder(user)
        user_check = await retrieve_user(user["phone_number"])
        phone_check = await retrieve_query({"email": user["email"]})
        if user_check or phone_check:
            raise DuplicateEntryException("Account with this Email or Phone No already exists")
        if encrypt_methods.decrypt_message(user["password"]):
            user["role"] = "user"
            new_user = await add_user(user)
            id = new_user.get("_id")
            if id:
                otp = generate_otp()
                _ = await update_user(id,{"verification_attempts": 0, "phone_number":"not verified" ,"otp": otp, "otp_expiry": datetime.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES), "verify":False})
            else:
                raise InternalServerErrorException("Something went wrong updating database.")
        # Send OTP via email
        if send_otp_sms(user["phone_number"], otp):
            data = {"id": id}
            return ResponseModel(data,"OTP sent to Phone Number.")
        else:
            raise InternalServerErrorException("An internal server error occurred while sending OTP")
    except NotFoundException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except DuplicateEntryException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except Exception as e:
        print(e)
        internal_server_exception = InternalServerErrorException("An internal server error occurred")
        exception_dict = internal_server_exception.to_dict()
        return JSONResponse(status_code=internal_server_exception.code, content=exception_dict)

@app.post("/api/login", tags=["Login"])
async def sign_up(user: UserLoginSchema = Body(...)):
    try:
        user = jsonable_encoder(user)
        key = identify_contact_info(user["id"])
        user_check = await retrieve_query({key: user["id"]})
        if user_check and encrypt_methods.decrypt_message(user_check["password"]) == encrypt_methods.decrypt_message(user.get("password")):
            token = encrypt_methods.generate_token(user_check)
            return TokenResponseModel(token, "Logged in successfully successfully")
        else:
            raise UnauthorizedException("Username or passowrd is incorrect.")
    except NotFoundException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except Exception as e:
        internal_server_exception = InternalServerErrorException("An internal server error occurred")
        exception_dict = internal_server_exception.to_dict()
        return JSONResponse(status_code=internal_server_exception.code, content=exception_dict)

@app.post("/api/otp-login")
async def login(id: str ):
    try:
        # Check if user exists
        user = await retrieve_query({"_id": id})
        print(user)
        if not user:
            raise NotFoundException(f"User {id} does not exsits.")

        # Generate and save OTP
        if user.get("otp") and user.get("otp_expiry") and user.get("otp_expiry") > datetime.now():
            otp = user.get("otp")
        else:
            otp = generate_otp()
            _ = await update_user(id,{"verification_attempts": 0, "otp": otp, "otp_expiry": datetime.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)})

            
        # Send OTP via email
        key = identify_contact_info(id)
        if key == "email":
            send_otp_email(id, otp)
        else:
            send_otp_sms(id, otp)
        data = {"id": id}
        return ResponseModel(data,f"OTP sent to {id}")
    except NotFoundException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except Exception as e:
        print(e)
        internal_server_exception = InternalServerErrorException("An internal server error occurred")
        exception_dict = internal_server_exception.to_dict()
        return JSONResponse(status_code=internal_server_exception.code, content=exception_dict)

# Verify OTP endpoint
@app.post("/api/verify-otp")
async def verify_user_otp(data: VerificationSchema = Body(...)):
    # Retrieve the stored user document from the database
    try:
        data = jsonable_encoder(data)
        id = data['id']
        otp = data['otp']
        stored_user = await retrieve_user(id)
        verification_attempts = stored_user.get("verification_attempts", 0)
        print(stored_user)
        verify = await verify_otp(stored_user, otp, verification_attempts)
        if verify:
            token = encrypt_methods.generate_token(stored_user)
            return TokenResponseModel(token, "OTP verification successful, Logged in successfully successfully")
        else:
            raise UnauthorizedException("OTP Verification Failed, Internal Server Error Occured")
    except NotFoundException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except Exception as e:
        print(e)
        internal_server_exception = InternalServerErrorException("An internal server error occurred")
        exception_dict = internal_server_exception.to_dict()
        return JSONResponse(status_code=internal_server_exception.code, content=exception_dict)

# Verify Signup OTP endpoint
@app.post("/api/verify-signup")
async def verify_user_otp(data: VerificationSchema = Body(...)):
    # Retrieve the stored user document from the database
    try:
        data = jsonable_encoder(data)
        id = data['id']
        otp = data['otp']
        stored_user = await retrieve_user(id)
        verification_attempts = stored_user.get("verification_attempts", 0)

        verify = await verify_signup_otp(stored_user, otp, verification_attempts)
        if verify:
            token = encrypt_methods.generate_token(stored_user)
            _ = await update_user(id,{"phone_number":id, "verify": True})
            return TokenResponseModel(token, "OTP verification successful, Signed Up successfully successfully")
        else:
            raise UnauthorizedException("OTP Verification Failed, An internal server error occurred")
    except NotFoundException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except UnauthorizedException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except Exception as e:
        print(e)
        internal_server_exception = InternalServerErrorException("An internal server error occurred")
        exception_dict = internal_server_exception.to_dict()
        return JSONResponse(status_code=internal_server_exception.code, content=exception_dict)