from django.urls import path

from .views import ContinueView


urlpatterns = [
    path("continue/", ContinueView.as_view(), name="continue"),
]
