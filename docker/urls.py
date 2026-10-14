import os

from django.conf import settings
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.static import serve

urlpatterns = [
	path('', include('nmapreport.urls')),
	path('report/', include('nmapreport.urls')),
	path('admin/', admin.site.urls),
	# App assets and generated PDF reports; served here because the
	# container runs gunicorn without a separate static file server.
	re_path(r'^static/(?P<path>.*)$', serve, {'document_root': os.path.join(settings.BASE_DIR, 'nmapreport', 'static')}),
]
