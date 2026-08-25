import pickle


def parse_profile(document):
    decoder = pickle.Unpickler(document)
    return decoder.load()
