from drf_spectacular.utils import OpenApiResponse, OpenApiExample
from .serializers import CommonErrorSerializer


HTTP404_EXAMPLE = OpenApiExample("http-404", {"message": "resource not found", "code": 404})
HTTP400_EXAMPLE = OpenApiExample("http-400", {"message": "request not understood", "code": 400})
WEBSERVER_404_RESPONSE = OpenApiResponse({'type': 'string', 'format': 'html', 'description': 'default 404 page'}, "webserver's HTML 404 page", examples=[OpenApiExample('404-page', "<html><title>page not found</title></html>")])
WEBSERVER_500_RESPONSE = OpenApiResponse({'type': 'string', 'format': 'html', 'description': 'default 500 page'}, "webserver's HTML 500 page", examples=[OpenApiExample('500-page', "<html><title>server error</title></html>")])



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
