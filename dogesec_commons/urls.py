"""
URL configuration for dogesec_commons project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework import routers
from dogesec_commons.stixifier.views import ExtractorsView, ProfileView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from dogesec_commons.objects import views as arango_views
router = routers.SimpleRouter(use_regex_path=False)

router.register('profiles', ProfileView, "profile-view")
# txt2stix views
router.register('extractors', ExtractorsView, "extractors-view")

## objects
regex_router = routers.SimpleRouter(use_regex_path=True)
regex_router.register("", arango_views.ObjectsWithReportsView, "object-view-orig")
regex_router.register('smos', arango_views.SMOView, "object-view-smo")
regex_router.register('scos', arango_views.SCOView, "object-view-sco")
regex_router.register('sros', arango_views.SROView, "object-view-sro")
regex_router.register('sdos', arango_views.SDOView, "object-view-sdo")
urlpatterns = [
    path(f'api/', include(router.urls)),
    path(f'objects/', include(regex_router.urls)),
    path('admin/', admin.site.urls),

    # YOUR PATTERNS
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    # Optional UI:
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
