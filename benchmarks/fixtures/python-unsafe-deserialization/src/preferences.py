import pickle


def import_preferences(request):
    return pickle.loads(request.body)
