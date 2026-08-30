from django.shortcuts import redirect


def continue_to(request):
    target = request.GET.get("next", "")
    destination = "/" + target
    return redirect(destination)
