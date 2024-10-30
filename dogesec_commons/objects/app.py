from django.apps import AppConfig

class ArangoObjectsViewApp(AppConfig):
    name = 'dogesec_commons.objects'
    label = 'dogesec_arango_objects_views'

    def ready(self) -> None:
        from .db_view_creator import startup_func
        startup_func()
        return super().ready()