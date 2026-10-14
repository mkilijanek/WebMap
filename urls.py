from django.contrib.auth.decorators import login_required
from django.urls import path
from . import views, api, pdf

# Every view requires a logged-in user. docker/settings.py also enables
# LoginRequiredMiddleware; the decorators keep the app protected when it is
# mounted in a project that does not.
urlpatterns = [
	path('', login_required(views.index), name='index'),
	path('setscanfile/<scanfile>', login_required(views.setscanfile), name='setscanfile'),
	path('<address>/', login_required(views.details), name='details'),
	path('port/<port>/', login_required(views.port), name='port'),
	path('service/<filterservice>/', login_required(views.index), name='service'),
	path('portid/<filterportid>/', login_required(views.index), name='portid'),
	path('api/setlabel/<objtype>/<label>/<hashstr>/', login_required(api.label), name='api_label'),
	path('api/rmlabel/<objtype>/<hashstr>/', login_required(api.rmlabel), name='api_rmlabel'),
	path('api/pdf/', login_required(api.genPDF), name='genPDF'),
	path('api/getcve/', login_required(api.getCVE), name='getCVE'),
	path('api/savenotes/', login_required(api.saveNotes), name='api_savenotes'),
	path('api/rmnotes/<hashstr>/', login_required(api.rmNotes), name='api_rmnotes'),
	path('api/<address>/<portid>/', login_required(api.port_details), name='api_port'),
	path('view/pdf/', login_required(pdf.reportPDFView), name='reportPDFView')
]
