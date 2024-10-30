from django.conf import settings

MAXIMUM_PAGE_SIZE = getattr(settings, 'MAXIMUM_PAGE_SIZE', 200)
DEFAULT_PAGE_SIZE = getattr(settings, 'DEFAULT_PAGE_SIZE', 50)

DB = settings.ARANGODB_DATABASE
DB_NAME = f"{DB}_database"
VIEW_NAME = getattr(settings, "VIEW_NAME", f"{DB}_view")