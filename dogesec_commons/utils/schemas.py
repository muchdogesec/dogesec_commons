from drf_spectacular.utils import OpenApiResponse, OpenApiExample
from .serializers import CommonErrorSerializer


HTTP404_EXAMPLE = OpenApiExample("http-404", {"message": "resource not found", "code": 404})
HTTP400_EXAMPLE = OpenApiExample("http-400", {"message": "request not understood", "code": 400})

WEBSERVER_404_RESPONSE = OpenApiResponse(CommonErrorSerializer, description="webserver's HTML 404 page", examples=[OpenApiExample('404-page', {"code": 404, "message": "non-existent page"})])
WEBSERVER_500_RESPONSE = OpenApiResponse(CommonErrorSerializer, description="webserver's HTML 500 page", examples=[OpenApiExample('500-page', {"code": 500, "message": "internal server error"})])


DEFAULT_400_RESPONSE = OpenApiResponse(
    CommonErrorSerializer,
    "The server did not understand the request",
    [
        HTTP400_EXAMPLE
    ],
)


DEFAULT_404_RESPONSE = OpenApiResponse(
    CommonErrorSerializer,
    "Resource not found",
    [
        HTTP404_EXAMPLE
    ],
)
