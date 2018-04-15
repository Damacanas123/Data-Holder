from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^createPerson/$', views.createPerson,name="Create Person"),
    url(r'^createData/$',views.addData,name="Add Data Field"),
    url(r'^updateData/$',views.updateData,name="Change Data Field"),
    url(r'^deletePlatform/$',views.deletePlatform,name="Delete Platform"),
    url(r'^getDataByName/$',views.getDataByName,name="Get Data By Name"),
    url(r'^authenticateFirst/$',views.authenticateFirst,name="First Authentication")
]
