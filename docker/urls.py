import os

from django.conf import settings
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_not_required
from django.urls import include, path, re_path
from django.views.static import serve
from nmapreport.auth import ThrottledLoginView

urlpatterns = [
	# Before the app include: its '<address>/' pattern would match 'login/'.
	path('login/', ThrottledLoginView.as_view(), name='login'),
	path('logout/', auth_views.LogoutView.as_view(), name='logout'),
	# App assets (CSS, JS, images) only; PDF reports are no longer written
	# here but returned directly by the authenticated api/pdf/ view.
	# Served here because the container runs gunicorn without a separate
	# static file server; public so the login page can load its CSS.
	re_path(r'^static/(?P<path>.*)$', login_not_required(serve), {'document_root': os.path.join(settings.BASE_DIR, 'nmapreport', 'static')}),
	path('', include('nmapreport.urls')),
	path('report/', include('nmapreport.urls')),
]
