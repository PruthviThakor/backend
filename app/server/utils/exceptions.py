class APIException(Exception):
    def __init__(self, error, code, message):
        self.error = error
        self.code = code
        self.message = message

    def to_dict(self):
        return {
            "error": self.error,
            "status": {
                "type": "failure",
                "code": self.code,
                "message": self.message
            }
        }

class InvalidInputException(APIException):
    def __init__(self, message):
        super().__init__("InvalidInput", 400, message)

class UnauthorizedException(APIException):
    def __init__(self, message):
        super().__init__("Unauthorized", 401, message)

class NotFoundException(APIException):
    def __init__(self, message):
        super().__init__("NotFound", 404, message)
        
class InternalServerErrorException(APIException):
    def __init__(self, message):
        super().__init__("InternalServerError", 500, message)
        
class DuplicateEntryException(APIException):
    def __init__(self, message):
        super().__init__("DuplicateEntry", 409, message)

class ConnectionErrorException(APIException):
    def __init__(self, message):
        super().__init__("ConnectionError", 503, message)
        
class InsufficientPermissionException(APIException):
    def __init__(self, message):
        super().__init__("InsufficientPermission", 403, message)