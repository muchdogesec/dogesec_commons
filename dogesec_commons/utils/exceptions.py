from rest_framework.views import exception_handler
from rest_framework.exceptions import ValidationError
from django.core import exceptions as django_exceptions



def custom_exception_handler(exc, context):
    if isinstance(exc, django_exceptions.ValidationError):
        exc = ValidationError(detail=exc.messages, code=exc.code)
    # if isinstance(exc, ValueError):
    #     exc = ValidationError(detail=str(exc), code=400)
    resp = exception_handler(exc, context)
    if resp is not None:
        if isinstance(resp.data, dict) and len(resp.data) == 1 and 'detail' in resp.data:
                resp.data = resp.data['detail']
        if isinstance(resp.data, str):
            resp.data = dict(code=resp.status_code, message=resp.data)
        if isinstance(resp.data, list):
            resp.data = dict(code=resp.status_code, details={'detail':resp.data})
        else:
            resp.data = dict(code=resp.status_code, details=resp.data)
        resp.data.setdefault('message', resp.status_text)
    return resp