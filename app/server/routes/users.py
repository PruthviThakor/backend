"""
Note: !!! This apis are in example phase and not for the use !!!
"""

from fastapi import APIRouter, Body, Depends, Path
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from server.utils.encrypt_methods import jwt_token_verification, jwt_admin_token_verification
from server.utils.exceptions import (
    InsufficientPermissionException,
    InternalServerErrorException,
    NotFoundException,
    DuplicateEntryException
)
from server.database import (
    add_user,
    delete_user,
    retrieve_user,
    retrieve_users,
    update_user,
)

from server.models.users import (
    ErrorResponseModel,
    ResponseModel,
    UserSchema,
    UpdateUserModel,
)

router = APIRouter()



@router.get("/{id}", response_description="User data retrieved")
async def get_user_data(payload: dict = Depends(jwt_token_verification), id: str = Path(...)):
    try:
        if id!=payload["username"]:
            raise InsufficientPermissionException("You can't access other user's data")
        user = await retrieve_user(id)
        if user:
            return ResponseModel(user, "User data retrieved successfully")
        return ErrorResponseModel("An error occurred.", 404, "User doesn't exist.")
    except NotFoundException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except InsufficientPermissionException as e:
        return JSONResponse(status_code=e.code, content=e.to_dict())
    except Exception as e:
        print(e)
        internal_server_exception = InternalServerErrorException("An internal server error occurred")
        exception_dict = internal_server_exception.to_dict()
        return JSONResponse(status_code=internal_server_exception.code, content=exception_dict)


