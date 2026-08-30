from urllib.parse import quote

from django.shortcuts import redirect


def continue_to(request):
    target = request.GET.get("next", "")
    destination = "/continue/?next=" + quote(target, safe="")
    return redirect(destination)
