from app import app
from flaskext.mysql import MySQL
mysql=MySQL()
SECRET_KEY=b'\xdf\x8b^\x7f\xd6\x8d\xca\x88\xeb\xae\x95\xe3R\xb6\xb1\x90\xa7\xa0\x1d\x06\xe4\xc0\x84\xbd-\x90\xd9\x15!\x7f*\xd7'#key_temporal
SALT='0a2QzbjQK0'
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'kd3n4505'
app.config['MYSQL_DATABASE_DB'] = 'mydb'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

app.config['CORS_HEADERS'] = "Content-Type"
app.config['CORS_RESOURCES'] = {r"/*": {"origins": "*"}}


