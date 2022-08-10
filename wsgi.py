from gevent.pywsgi import WSGIServer
from gevent import monkey
monkey.patch_all()
import werkzeug

from app import app
import os


http_server = WSGIServer(('0,0,0,0', int(os.environ['PORT_APP'])), app)
http_server.serve_forever()