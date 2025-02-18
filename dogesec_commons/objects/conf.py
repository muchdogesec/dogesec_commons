from django.conf import settings

MAXIMUM_PAGE_SIZE = getattr(settings, 'MAXIMUM_PAGE_SIZE', 200)
DEFAULT_PAGE_SIZE = getattr(settings, 'DEFAULT_PAGE_SIZE', 50)

DB = settings.ARANGODB_DATABASE
DB_NAME = f"{DB}_database"
ARANGODB_DATABASE_VIEW = getattr(settings, "ARANGODB_DATABASE_VIEW", f"{DB}_view")