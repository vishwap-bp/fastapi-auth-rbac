from typing import Generic, TypeVar, Optional, Any
from pydantic import BaseModel, ConfigDict

T = TypeVar("T")

class ApiResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(from_attributes=True)
    status: bool
    statusCode: int
    message: str
    data: Optional[T] = None
