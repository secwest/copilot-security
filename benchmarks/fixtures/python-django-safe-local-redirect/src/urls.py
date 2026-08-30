from django.urls import path

from .views import continue_to


urlpatterns = [
    path("continue/", continue_to, name="continue"),
]
