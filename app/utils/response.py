from typing import Any, Optional
from fastapi.responses import JSONResponse

def success_response(data: Any = None, message: str = "Success", status_code: int = 200) -> JSONResponse:
    content = {
        "status": True,
        "statusCode": status_code,
        "message": message,
        "data": data
    }
    return JSONResponse(status_code=status_code, content=content)

def error_response(message: str, status_code: int = 400, data: Optional[Any] = None) -> JSONResponse:
    content = {
        "status": False,
        "statusCode": status_code,
        "message": message,
        "data": data
    }
    return JSONResponse(status_code=status_code, content=content)
