from app import app
from flaskext.mysql import MySQL
mysql=MySQL()
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'kd3n4505'
app.config['MYSQL_DATABASE_DB'] = 'mydb_test'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

app.config['CORS_HEADERS'] = "Content-Type"
app.config['CORS_RESOURCES'] = {r"/*": {"origins": "*"}}


