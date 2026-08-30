from django.shortcuts import redirect
from django.views import View


class ContinueView(View):
    def post(self, request):
        target = request.POST.get("next", "")
        destination = "/" + target
        return redirect(destination)
