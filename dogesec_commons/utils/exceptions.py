from rest_framework.views import exception_handler
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.core import exceptions as django_exceptions
from django.http import JsonResponse, Http404
import rest_framework.exceptions
import django.db.models.deletion


def custom_exception_handler(exc, context):
    if isinstance(exc, django_exceptions.ValidationError):
        exc = ValidationError(detail=exc.messages, code=exc.code)
    
    if isinstance(exc, django.db.models.deletion.ProtectedError):
        return JsonResponse({'code': 403, 'message': "cannot delete object(s) because they are referenced through protected foreign keys.", 'details': {'protected_objects': [str(f) for f in exc.protected_objects]}}, status=403)
        
    resp = exception_handler(exc, context)
    if resp is not None:
        if isinstance(resp.data, dict) and 'detail' in resp.data:
                resp.data = resp.data['detail']
        if isinstance(resp.data, str):
            resp.data = dict(code=resp.status_code, message=resp.data)
        if isinstance(resp.data, list):
            resp.data = dict(code=resp.status_code, details={'detail':resp.data})
        else:
            resp.data = dict(code=resp.status_code, details=resp.data)
        resp.data.setdefault('message', resp.status_text)
        resp = JsonResponse(data=resp.data, status=resp.status_code)
    return resp