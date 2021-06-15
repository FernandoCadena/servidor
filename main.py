from functools import cached_property, wraps
from PyPDF2.pdf import PageObject
import pymysql
from werkzeug.datastructures import native_itermethods
from werkzeug.wrappers import ResponseStreamMixin
from app import app
from config import SECRET_KEY, mysql, SALT
from flask import json, jsonify
from flask import request
import hashlib
from Crypto.PublicKey import RSA
import os
import base64
from Crypto.Util.number import long_to_bytes
import datetime
import jwt
import random
import PyPDF2
import io


####DEFINICION DE FUNCIONES Y UTILIDADES#######

def unpadhex(cad):
	return (cad[:64])

def padhex(cad):
	new=cad+os.urandom(32).hex()
	#xor(new,random_seed())
	return('0x'+new)

def limpiar_cad(cadena):
	bad_chars=['\'','"','#','&','(',')','[',']','{','}','-','=','_']
	for i in bad_chars:
		cadena=cadena.replace(i,"")
	return cadena
def token_required(f):
	@wraps(f,)
	def decorated(*args, **kwargs):
		if 'Authorization' in request.headers:
			token = request.headers['Authorization']
			print (token)
		if not 'Authorization' in request.headers:
			return jsonify({'message':'Error no Token Header'},403)

		if not token:
			return jsonify({'message' : 'No Token'}), 403
		try: 
			data = jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
		except:
			return jsonify({'message' : 'Token invalido!'}, 403)
		return f(data,*args, **kwargs)
	return decorated
###TEST####
#curl -X POST -H 'Content-Type: application/json,' -H 'x-access-tokens:' -i 'http://127.0.0.1/auth' 


def firmar(data):
	key = RSA.importKey(open('test1.pem',"r").read())
	_d=key.d
	_n=key.n
	_Element=data
	h=hashlib.sha256()
	h.update(_Element.encode())
	_hash=h.hexdigest()
	_hash=padhex(_hash)
	_sing=pow(int(_hash,16),_d,_n)
	_firma=str(base64.b64encode(long_to_bytes(_sing)).decode("utf-8"))
	return _firma



"""@app.route('/auth', methods=['POST'])
@token_required
def auth(data):
	rutas1=["/alumno","/profile"]
	rutas2=["/profesor","reactivos"]
	rutas0=["/admin","/activar"]
	_json = request.json
	ruta=_json['ruta']
	if ruta in rutas0:
		if(data['rol']==0):
			respone = jsonify(data)
			respone.status_code = 200
			return respone
		else:
			return not_found()
	if ruta in rutas1:
		print (type(data))
		print (data)
		if(data['rol']==1):
			respone = jsonify(data)
			respone.status_code = 200
			return respone
		else:
			return not_found()
	if ruta in rutas2:
		if(data['rol']==2):
			respone = jsonify(data)
			respone.status_code = 200
			return respone
		else:
			return not_found()
	"""



#curl -X GET -i 'http://127.0.0.1:4443/pdf?id=test'
@app.route('/pdf')
#@token_required
def emp():
	_id=request.args.get('id')#"test"
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		cursor.execute("SELECT * FROM evaluacion_alumno INNER JOIN evaluacion_profesor ON evaluacion_alumno.evaluacion_id_evaluacion=evaluacion_profesor.evaluacion_id_evaluacion WHERE alumno_id_alumno=%s",_id)
		_temp=cursor.fetchone()
		cursor.execute("SELECT nombre FROM materia WHERE id_materia=(SELECT id_materia FROM evaluacion WHERE id_evaluacion=%s)",_temp['evaluacion_id_evaluacion'])
		_materia=cursor.fetchone()
		_temp['materia']=_materia['nombre']
		print (_temp)
		print(type(_temp))
		cursor.execute("SELECT nombre, apellidos FROM usuario WHERE id_usuario=(SELECT usuario_id_usuario FROM alumno WHERE id_alumno=%s)",_temp['alumno_id_alumno'])
		_name=cursor.fetchone()
		_nombre=_name['nombre']+" "+_name['apellidos']
		_cadena=str(_temp['alumno_id_alumno'])+"||"+str(_temp['evaluacion_id_evaluacion'])+"||"+str(_temp['materia'])+"||"+str(_temp['calificacion'])+"||"+str(_temp['fecha_aplicacion'])+"||"+str(_nombre)
		print(_cadena)
		_firma=firmar(_cadena)
		_temp["cadena"]=_cadena
		_temp["firma"]=_firma
		respone = jsonify(_temp)
		respone.status_code = 200
		return respone
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()



#curl -X POST -H 'Content-Type: application/json' -H 'x-access-tokens: TOKEN' -i 'http://127.0.0.1:4443/crea-eval' --data '{"id_usuario":"102","materia":"Materia1","nombre_eval":"Evaluacion primer nivel","duracion":60,"ids_reactivos":[1,2,3,4,5]}'
@app.route('/crea-eval', methods=['POST'])
@token_required
def add_eval(data):#data
	try:
		_json = request.json
		print (_json)
		#_id = _json['id_eval']
		_id_eval=str(random.randint(1,21474)) +str(random.randint(1,83647))
		_id_user = _json['id_usuario']
		_materia = _json['materia']
		_ids_reactivos = _json['ids_reactivos']
		_titulo_eval=_json['nombre_eval']
		#_estado=_json['estado']
		_duracion=_json['duracion']
		#_temp=''
		#print (_ids_reactivos)
		#print (type(_ids_reactivos))
		if _id_user and _materia and  _ids_reactivos and _titulo_eval  and request.method == 'POST':
			sqlQuery = "INSERT INTO evaluacion VALUES(%s,(SELECT id_materia FROM materia WHERE nombre=%s LIMIT 1),%s,1,%s) "
			bindData=(int(_id_eval),str(_materia), str(_titulo_eval),int(_duracion))
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute(sqlQuery, bindData)
			conn.commit()
			for i in range(len(_ids_reactivos)):
					print(_ids_reactivos[i])
					sqlQuery = "INSERT INTO reactivo_evaluacion values(%s,%s)"
					bindData=(int(_id_eval), int(_ids_reactivos[i]))
					cursor.execute(sqlQuery, bindData)
			conn.commit()
			respone = jsonify({"id_evaluacion":_id_eval})
			respone.status_code = 200
			return respone
		else:
			return not_found()
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()

#curl -i 'http://127.0.0.1:4443/reactivos?materia=Materia1&nivel=Nivel1'
@app.route('/reactivos')
@token_required
def filtro_reactivos(data):#data
	_materia=request.args.get('materia')#"test"
	_nivel=request.args.get('nivel')
	_nivel=limpiar_cad(_nivel)
	_materia=limpiar_cad(_materia)
	if(_nivel and _materia):
		try:
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			SqlQuery="SELECT id_reactivo,pregunta,tipo FROM reactivo WHERE id_materia=(SELECT id_materia FROM materia WHERE nombre=%s AND nivel=%s LIMIT 1)"
			bindData=(str(_materia),str(_nivel))
			cursor.execute(SqlQuery,bindData)
			empRows = cursor.fetchall()
			respone = jsonify(empRows)
			respone.status_code = 200
			return respone
		except Exception as e:
			print(e)
		finally:
			cursor.close() 
			conn.close()
	if(_materia):
		try:
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT id_reactivo, pregunta FROM reactivo WHERE id_materia=(SELECT id_materia FROM materia WHERE nombre=%s",_materia)
			empRows = cursor.fetchall()
			respone = jsonify(empRows)
			respone.status_code = 200
			return respone
		except Exception as e:
			print(e)
		finally:
			cursor.close() 
			conn.close()
	else:
		return not_found()

@app.route('/usr', methods=['POST'])
def emp_id():
	_json = request.json
	_id = _json['id_usuario']
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		cursor.execute("SELECT id_usuario, nombre, apellidos, correo, FROM usuario WHERE id_usuario =%s", _id)
		empRow = cursor.fetchone()
		respone = jsonify(empRow)
		respone.status_code = 200
		return respone
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()

#Obtiene los reactivos de una determinada evaluacion por medio del ID de la evalicion 
#curl -X POST -H 'Content-Type: application/json' -H 'x-access-tokens: TOKEN' -i 'http://127.0.0.1:4443/obtener-eval' --data '{"eval":"1"}'
@app.route('/obtener-eval',methods=['POST'])
#@token_required
def obten_quiz():#data
	_json = request.json
	_quiz=_json['eval']#"test"
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		cursor.execute("SELECT reactivo_id_reactivo FROM reactivo_evaluacion WHERE evaluacion_id_evaluacion=%s",_quiz)
		empRows = cursor.fetchall()
		reactivos = empRows#["reactivo_id_reactivo"]
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		_reactivos=[{"id_evaluacion":_quiz}]
		for i in range(len(reactivos)):
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT id_opcion,opcion,indice FROM opcion WHERE reactivo_id_reactivo=%s LIMIT 1",str(reactivos[i]["reactivo_id_reactivo"]))
			#_reactivos.append(reactivos[i])
			reactivos[i]["opciones"]=cursor.fetchall()
		print (reactivos)		
		respone = jsonify(reactivos)
		respone.status_code = 200
		return respone
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()

#
@app.route('/calificar', methods=['POST'])
@token_required
def calif_eval(data):#data
	_date = datetime.datetime.now()
	_fecha=str(_date.year)+':'+str(_date.month)+':'+str(_date.day)+' '+str(_date.hour)+':'+str(_date.min)+':'+str(_date.second) 
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		_json = request.json
		print (_json)
		_id_usuario = _json['id_usuario']
		_id_eval = _json['id_eval']
		_respuestas=_json['respuestas']
		#print (_respuestas[0]['idReactivo'])
		_temp_cal=0
		for i in _respuestas:
			sqlQuery = "INSERT INTO respuesta_alumno_reactivo VALUES(%s,%s,%s,%s)"
			bindData=(str(_id_usuario),i['idReactivo'], int(_id_eval),str(i['resp']))
			cursor.execute(sqlQuery, bindData)
			_indice=cursor.execute("SELECT opcion_correcta,tipo FROM reactivo WHERE id_reactivo =%s", i['idReactivo'])
			if _indice['tipo']=="ra":
				s#calificar RAs
			else:
				if _indice['opcion_correcta']==i['resp']:
					_temp_cal+=1
		conn.commit()
		_temp_final=((len(_respuestas))/100)*_temp_cal
		sqlQuery = "INSERT INTO evaluacion_alumno VALUES(NULL,%s,%s,%s,%s)"
		bindData=(str(_id_usuario),int(_id_eval),int(_temp_final),str(_fecha))
		cursor.execute(sqlQuery,bindData)
		conn.commit()
		respone = jsonify({"cal":_temp_cal})
		respone.status_code = 200
		return respone
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()


@app.route('/update', methods=['PUT'])
@token_required
def update_emp(data):
	try:
		_json = request.json
		_id = _json['id_usuario']
		_nombre = _json['nombre']
		_apellidos = _json['apellidos']
		_correo = _json['correo']
		#_pass = _json['password']	esto es opcional porque si se actualiza la contrasena hay que validar la anterior y generar un nuevo hash	
		#_role = _json['role']		
		# validate the received values
		if _id and _nombre and _apellidos and _correo and request.method == 'PUT':			
			sqlQuery = "UPDATE usuario SET id_usuario=%s, nombre=%s, apellidos=%s, correo=%s WHERE id_usuario=%s"
			bindData = (_id, _nombre, _apellidos, _correo, _id)
			conn = mysql.connect()
			cursor = conn.cursor()
			cursor.execute(sqlQuery, bindData)
			conn.commit()
			respone = jsonify('Employee updated successfully!')
			respone.status_code = 200
			return respone
		else:
			return not_found()
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()
		
@app.route('/delete/<int:id>', methods=['DELETE'])
@token_required
def delete_emp(data,id):
	try:
		conn = mysql.connect()
		cursor = conn.cursor()
		cursor.execute("DELETE FROM usaurio WHERE id_usuario =%s", (id,))
		conn.commit()
		respone = jsonify('Eliminado!')
		respone.status_code = 200
		return respone
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()

#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1:4443/login' --data '{"username":"a@b.c","password":"test","rol":"2"}'
#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1:4443/login' --data '{"username":"a@b.c","password":"test","rol":"1"}'
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		# Create variables for easy access
		_json = request.json
		_user=_json['username']
		_pass=_json['password']
		_rol=_json['rol']
		_user=limpiar_cad(_user)
		_hash=hashlib.sha256()
		_hash.update(SALT.encode()+_pass.encode())
		_hashdigest=str(_hash.hexdigest())
		conn = mysql.connect()
		cursor = conn.cursor()
		cursor.execute('SELECT id_usuario, nombre, apellidos, correo, activo FROM usuario WHERE correo = %s AND password = %s', (_user, _hashdigest))
		account = cursor.fetchone()
		if (_rol=="1"):
			cursor = conn.cursor()
			cursor.execute('SELECT id_profesor FROM profesor WHERE usuario_id_usuario = %s', (account[0]))
			_datos=cursor.fetchone()
		if (_rol=="2"):
			cursor = conn.cursor()
			cursor.execute('SELECT id_alumno FROM alumno WHERE usuario_id_usuario = %s', (account[0]))
			_datos=cursor.fetchone()
		cursor.close() 
		conn.close()
		#print(_hashdigest)
		print(account)
		if (_datos):
			#print(type(account))
			_nom=account[1]+' '+account[2]
			if account:
				if account[4]==1:
					access_token = jwt.encode({'id_usuario': _datos[0],'rol':_rol,'nombre':_nom, 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=1200)},SECRET_KEY,algorithm="HS256")
					respone = jsonify({'message':'Login Exitoso!','token': access_token })
					respone.status_code = 200
					return respone
				else:
					respone = jsonify({'message':'Usuario inactivo, contacta al administrador'})
					respone.status_code = 200
					return respone	
			else:
				respone =jsonify({'message':'Incorrect username/password!'})
				respone.status_code=301
				return respone
		else:
			respone =jsonify({'message':'Usuario incorrecto/Usuario no registrado'})
			respone.status_code=301
			return respone


#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1:4443/add' --data '{"id_usuario":"103","nombre":"Fernando","apellidos":"cadena m","correo":"a@b.c","password":"test","role":"2"}'
@app.route('/add', methods=['POST'])
def add_emp():
	try:
		_json = request.json
		print (_json)
		_id = _json['id_usuario']
		_nombre = _json['nombre']
		_apellidos = _json['apellidos']
		_correo = _json['correo']
		_pass = _json['password']		
		_role = int(_json['role'])
		_hash=hashlib.sha256()
		_hash.update(SALT.encode()+_pass.encode())
		_hashdigest=str(_hash.hexdigest())
		print (_hashdigest)
		if _id and _nombre and _apellidos and _correo and _pass and _role and request.method == 'POST':
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			if(_role==2):
				_exist="SELECT * FROM alumno WHERE id_alumno=%s"
				_bindData=(str(_id))
				cursor.execute(_exist, _bindData)
				_res=cursor.fetchone()
				if (_res):
					respone = jsonify({'message':'Alumno ya Existe'})
					respone.status_code = 302
					return respone
				else:
					_exist="SELECT id_usuario FROM usuario WHERE nombre=%s AND apellidos=%s AND correo=%s"
					_bindData=(str(_nombre),str(_apellidos),str(_correo))
					cursor.execute(_exist, _bindData)
					print ("1")
					_quest=cursor.fetchall()
					if not _quest:	
						sqlQuery = "INSERT INTO usuario VALUES(NULL,%s, %s, %s, %s,0)"
						bindData=(str(_nombre), str(_apellidos), str(_correo), str(_hashdigest))
						cursor.execute(sqlQuery, bindData)
						conn.commit()
						sqlQuery="INSERT INTO alumno VALUES(%s,(SELECT id_usuario FROM usuario WHERE correo=%s))"
						bindData=(str(_id),str(_correo))
						cursor.execute(sqlQuery, bindData)
						conn.commit()
						respone = jsonify({'message':'Registro Exitoso!'})
						respone.status_code = 200
						return respone
					else:
						sqlQuery="INSERT INTO alumno VALUES(%s,(SELECT id_usuario FROM usuario WHERE correo=%s))"
						bindData=(str(_id),str(_correo))
						cursor.execute(sqlQuery, bindData)
						conn.commit()
						respone = jsonify({'message':'Registro Exitoso!'})
						respone.status_code = 200
						return respone
			if (_role==1):
				_exist="SELECT * FROM profesor WHERE id_profesor=%s"
				_bindData=(str(_id))
				cursor.execute(_exist, _bindData)
				_res=cursor.fetchone()
				if (_res):
					respone = jsonify({'message':'Profesor ya Existe'})
					respone.status_code = 302
					return respone
				else:
					_exist="SELECT id_usuario FROM usuario WHERE nombre=%s AND apellidos=%s AND correo=%s"
					_bindData=(str(_nombre),str(_apellidos),str(_correo))
					cursor.execute(_exist, _bindData)
					_quest=cursor.fetchone()
					if not _quest:	
						sqlQuery = "INSERT INTO usuario VALUES(NULL,%s, %s, %s, %s,0)"
						bindData=(str(_nombre), str(_apellidos), str(_correo), str(_hashdigest))
						cursor.execute(sqlQuery, bindData)
						conn.commit()
						sqlQuery="INSERT INTO profesor VALUES(%s,(SELECT id_usuario FROM usuario WHERE correo=%s))"
						bindData=(str(_id),str(_correo))
						cursor.execute(sqlQuery, bindData)
						conn.commit()
						respone = jsonify({'message':'Registro Exitoso!'})
						respone.status_code = 200
						return respone
					else:
						sqlQuery="INSERT INTO profesor VALUES(%s,(SELECT id_usuario FROM usuario WHERE correo=%s))"
						bindData=(str(_id),str(_correo))
						cursor.execute(sqlQuery, bindData)
						conn.commit()
						respone = jsonify({'message':'Registro Exitoso!'})
						respone.status_code = 200
						return respone
		else:
			return not_found()
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()


#curl -X POST -H 'Content-Type: application/json' -H 'x-access-tokens: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYUBiLmMiLCJyb2wiOiJhbHVtbm8iLCJleHAiOjE2MjE4MTA5NTJ9.Qd9Ozma84xeMxuOpkqHPX_BWw5Lhaph2XSgMBZqHJg4' -i 'http://127.0.0.1/creaFirma' --data '{"data":"hola"}'
@app.route('/creaFirma', methods=['POST'])
@token_required
def signature(data):
	_data=data
	key = RSA.importKey(open('test1.pem',"r").read())
	_d=key.d
	_n=key.n
	if request.method == 'POST':
		#
		_json = request.json
		_Element=_json['data']
		h=hashlib.sha256()
		h.update(_Element.encode())
		_hash=h.hexdigest()
		_hash=padhex(_hash)
		_sing=pow(int(_hash,16),_d,_n)
		respone=jsonify({"firma": str(base64.b64encode(long_to_bytes(_sing)).decode("utf-8"))})
		respone.status_code = 200
		return respone

#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1/validaFirma' --data '{"data":"hola","firma":"b'WSbh21czm9VSV8dQQDWcgew00EvV2evlCdSFbTEExoyDhub8Xh5dCenGdazlU9HTzEggmaOqUsihLyHzSlkadrCtui+3aaJgI4sU4MO4vBuOZKQ96iHGtkWNNW2XjP+waAVTy6N5fsI2+lId8E4OUXc6nYeqCtk2EpphaeFqLzCAIi1l09zXNW5gYUjKlvT0oMomXLEOZbaENwZngpYrhNknYWVuQMw99YuMLeiaC2gBJFLvdCl+p0MJmDV85iE+Zcya7Dw9DzZm8kSqIL6XUCMS9LVN1R7FmjHIr5/PzCFgKr3QzOJPeLoabXH/UR9ALmecq1vG1aqdj4SGqbnPxw=='"}'
@app.route('/validaFirma', methods=['POST'])
@token_required
def desing(data):
	key = RSA.importKey(open('test1.pem',"r").read())
	_n=key.n
	_e=key.e
	if request.method == 'POST':
		#	
		_json = request.json
		_pdf=_json['archivo']
		_file=base64.b64decode(_pdf)
		document=io.BytesIO(_file)
		pdfRead=PyPDF2.PdfFileReader(document)
		page=pdfRead.getPage(0)
		_datos=page.extractText()
		inicio_firma=_datos.find("$$")
		fin_firma=_datos.find("$$$")
		inicio_cadena=_datos.find("@@")
		fin_cadena=_datos.find("@@@")
		_Element=_datos[inicio_cadena+2:fin_cadena]
		_Element.replace("-\n","")
		_firma=_datos[inicio_firma+2:fin_firma]
		#_json = request.json
		#_Element=_json['data']
		hash=hashlib.sha256()
		hash.update(_Element.encode())
		_firma=_json['firma']
		firma_='0x'+((base64.b64decode(_firma)).hex())
		_nuevo=pow(int(firma_,16),_e,_n)
		_H=(long_to_bytes(_nuevo).hex())[:64]
		if(_H==hash.hexdigest()):
			respone=jsonify({"message": "OK"})
			respone.status_code = 200
			return respone

#cargar reactivos
@app.route('/csv', methods=['POST'])
@token_required
def upload_csv(data):
	_json = request.json
	for i in range(1,len(_json['data'])-1):
		_temp=(_json['data'])[i]
		_dicc= (_temp['data'])
		_pregunta = _dicc[0]
		_resp = _dicc[1]
		_tipo = _dicc[2]
		_materia = _dicc[3]
		_numOp = _dicc[4]
		sqlQuery = "INSERT INTO reactivo (pregunta, opcion_correcta, tipo, id_materia) VALUES(%s, %s, %s, (SELECT id_materia FROM materia WHERE nombre=%s))"
		bindData=(_pregunta.encode('utf8'), str(_resp),str(_tipo), str(_materia))
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		cursor.execute(sqlQuery, bindData)
		conn.commit()
		cursor.execute('SELECT id_reactivo FROM reactivo WHERE pregunta = %s', (_pregunta))
		id_reactivo = cursor.fetchone()
		#print (id_reactivo['id_reactivo'])
		for j in range(5,4+int(_numOp)+1):
			cursor.execute('INSERT INTO opcion VALUES(NULL,%s,%s,%s)', (int(id_reactivo['id_reactivo']),_dicc[j],chr(ord('a')+j-5)))
			conn.commit()

	respone = jsonify('Reactivos cargados con Exito!')
	respone.status_code = 200
	cursor.close() 
	conn.close()
	return respone


@app.route('/add-reactivo', methods=['POST'])
@token_required
def new_reactivo(data):
	_json = request.json
	print(_json)
	_pregunta=_json['reactivo']
	_resp = _json['opCorrecta']
	_tipo = _json['tipo']
	_materia = _json['materia']
	_opciones = _json['opciones']
	sqlQuery = "INSERT INTO reactivo (pregunta, opcion_correcta, tipo, id_materia) VALUES(%s, %s, %s, (SELECT id_materia FROM materia WHERE nombre=%s LIMIT 1))"
	bindData=(_pregunta.encode('utf8'), str(_resp),str(_tipo), str(_materia))
	conn = mysql.connect()
	cursor = conn.cursor(pymysql.cursors.DictCursor)
	cursor.execute(sqlQuery, bindData)
	conn.commit()
	cursor.execute('SELECT id_reactivo FROM reactivo WHERE pregunta = %s', (_pregunta))
	id_reactivo = cursor.fetchone()
	#print (id_reactivo['id_reactivo'])
	print (_opciones[0]['op'])
	for j in _opciones:
		print(j)
		cursor.execute('INSERT INTO opcion VALUES(NULL,%s,%s,%s)', (int(id_reactivo['id_reactivo']),j['op'],(j['letra'].lower())))
	conn.commit()
	respone = jsonify('Reactivo cargado con Exito!')
	respone.status_code = 200
	cursor.close() 
	conn.close()
	return respone


@app.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Record not found: ' + request.url,
    }
    respone = jsonify(message)
    respone.status_code = 404
    return respone

if __name__ == "__main__":
    app.run(debug=False,port=4443)
