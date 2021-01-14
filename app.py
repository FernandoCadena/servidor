from flask import Flask
from flask_cors import CORS, cross_origin

app = Flask(__name__)
#CORS(appcors = CORS(app, resources={r"add/*": {"origins": "*"}}))
#CORS(app)
cors = CORS(app)