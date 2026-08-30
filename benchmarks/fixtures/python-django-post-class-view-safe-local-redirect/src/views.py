from urllib.parse import quote

from django.shortcuts import redirect
from django.views import View


class ContinueView(View):
    def post(self, request):
        target = request.POST.get("next", "")
        destination = "/continue/?next=" + quote(target, safe="")
        return redirect(destination)
