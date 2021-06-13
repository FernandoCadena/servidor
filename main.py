from functools import wraps
import pymysql
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


####DEFINICION DE FUNCIONES Y UTILIDADES#######

def unpadhex(cad):
	return (cad[:64])

def padhex(cad):
	new=cad+os.urandom(32).hex()
	#xor(new,random_seed())
	return('0x'+new)

def limpiar_cad(cadena):
	bad_chars=['\'','"','#','&','(',')','[',']','{','}','-']
	for i in bad_chars:
		cadena=cadena.replace(i,"")
	return cadena
def token_required(f):
	@wraps(f,)
	def decorated(*args, **kwargs):
		if 'x-access-tokens' in request.headers:
			token = request.headers['x-access-tokens']
			print (token)
		if not 'x-access-tokens' in request.headers:
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

@app.route('/auth', methods=['POST'])
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
@app.route('/c', methods=['GET'])
def consulta():
	sqlQuery = "SELECT * FROM usuario;"
	conn = mysql.connect()
	cursor = conn.cursor()
	cursor.execute(sqlQuery)
	conn.commit()
	respone = jsonify('True')
	respone.status_code = 200
	return respone
"""


#curl -X GET -i 'http://127.0.0.1:5000/profile?id=test'
@app.route('/profile')
@token_required
def emp(data):
	_id=request.args.get('id')#"test"
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		cursor.execute("SELECT id_usuario, nombre, correo FROM usuario WHERE id_usuario=%s",_id)
		empRows = cursor.fetchall()
		respone = jsonify(empRows)
		respone.status_code = 200
		return respone
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()


@app.route('/crea-eval', methods=['POST'])
@token_required
def add_eval(data):
	try:
		_json = request.json
		print (_json)
		#_id = _json['id_eval']
		_id_eval = _json['id_evaluacion']
		_id_user = _json['id_usuario']
		_materia = _json['materia']
		_fecha = _json['date']
		_tipo = _json['tipo']
		_ids_reactivos = _json['ids_reactivos']
		_titulo_eval=_json['nombre_eval']
		_estado=_json['estado']
		_reactivos=''
		_temp=''
		print (_ids_reactivos)
		#print (type(_ids_reactivos))
		print (_reactivos)
		if _id_user and _materia and _fecha and _tipo and _ids_reactivos and _titulo_eval and _estado and request.method == 'POST':
			sqlQuery = "INSERT INTO evaluacion(id_evaluacion, id_materia, fecha, nombre_eval) VALUES(%s, (SELECT id_materia FROM materia WHERE nombre=%s), %s, %s)"
			bindData=(str(_id_eval), str(_materia), str(_fecha), str(_titulo_eval), str(_estado))
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute(sqlQuery, bindData)
			conn.commit()
			for i in range(len(_ids_reactivos)):
					sqlQuery = "INSERT INTO reactivo_evaluacion(evaluacion_id_evaluacion, reactivo_id_reactivo) VALUES(%s,%s)"
					bindData=(str(_id_eval), str(_reactivos[i]))
			respone = jsonify('Registro Exitoso!')
			respone.status_code = 200
			return respone
		else:
			return not_found()
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()


@app.route('/reactivos')
@token_required
def filtro_reactivos(data):
	_materia=request.args.get('materia')#"test"
	_nivel=request.args.get('nivel')
	if(_materia):
		try:
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT id_reactivo, pregunta, op1, op2, op3, op3, nivel, materia FROM reactivo_opm WHERE materia=%s",_materia)
			empRows = cursor.fetchall()
			respone = jsonify(empRows)
			respone.status_code = 200
			return respone
		except Exception as e:
			print(e)
		finally:
			cursor.close() 
			conn.close()
	if(_nivel):
		try:
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT id_reactivo, pregunta, op1, op2, op3, op3, nivel, materia FROM reactivo_opm WHERE nivel=%s",_nivel)
			empRows = cursor.fetchall()
			respone = jsonify(empRows)
			respone.status_code = 200
			return respone
		except Exception as e:
			print(e)
		finally:
			cursor.close() 
			conn.close()

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
#curl -X POST -H 'Content-Type: application/json' -H 'x-access-tokens: TOKEN' -i 'http://127.0.0.1:4443/quiz' --data '{"eval":"1"}'
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
		reactivos= empRows#["reactivo_id_reactivo"]
		#print (reactivos)
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		_reactivos=[{"id_evaluacion":_quiz}]
		for i in range(len(reactivos)):
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT id_opcion,opcion,indice FROM opcion WHERE reactivo_id_reactivo=%s",str(reactivos[i]["reactivo_id_reactivo"]))
			_reactivos.append(cursor.fetchall())
		print (_reactivos)		
		respone = jsonify(_reactivos)
		respone.status_code = 200
		return respone

	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()


@app.route('/calificar', methods=['POST'])
#@token_required
def calif_eval():#data
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		_json = request.json
		print (_json)
		_respuestas=_json['respuestas']
		#print (_respuestas[0]['idReactivo'])
		_temp_cal=0
		for i in _respuestas:
			_indice=cursor.execute("SELECT opcion_correcta FROM reactivo WHERE id_reactivo =%s", i['idReactivo'])
			_respuesta=cursor.execute("SELECT  FROM reactivo WHERE id_reactivo =%s",_indice)
			if _respuesta==i['resp']:
				_temp_cal+=1
		
		_temp_final=((len(_respuestas))/100)*_temp_cal
		"""_id_eval = _json['id_eval']
		#_calificacion = _json['calificacion']
		_respuestas = _json['respuestas']
		_id_usuario = _json['id_usuario']
		#_id_calificacion = _json['calificacion']
		preguntas=_respuestas.split(',')
		_temp_cal=0
		for i in range(len(preguntas)):
			_question=preguntas[i].split('-')[0]
			_answer=preguntas[i].split('-')[1]
			cursor.execute("SELECT op_correcta FROM reactivo_opm WHERE id_reactivc =%s", _question)
			if(_answer==cursor.fetchone()):
				_temp_cal+=1
		_temp_final=((len(preguntas))/100)*_temp_cal
		if _id_eval and _respuestas and _id_usuario and _temp_final and request.method == 'POST':
			sqlQuery = "INSERT INTO calificacion VALUES(%s, %s, %s, %s, %s)"
			bindData=(str(_id_eval), _temp_final, str(_respuestas), str(_id_usuario))
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute(sqlQuery, bindData)
			conn.commit()
			respone = jsonify('La calificación se registro con Exito!')
			respone.status_code = 200
			return respone
		else:
			return not_found()"""
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()


@app.route('/update', methods=['PUT'])
@token_required
def update_emp():
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
def delete_emp(id):
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

#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1:4443/login' --data '{"username":"a@b.c","password":"test","rol":"alumno"}'
#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1:4443/login' --data '{"username":"a@b.c","password":"test","rol":"profesor"}'
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
		if (_rol==1):
			cursor = conn.cursor()
			cursor.execute('SELECT id_profesor FROM profesor WHERE usuario_id_usuario = %s', (account[0]))
			_datos=cursor.fetchone()
		if (_rol==2):
			cursor = conn.cursor()
			cursor.execute('SELECT id_alumno FROM alumno WHERE usuario_id_usuario = %s', (account[0]))
			_datos=cursor.fetchone()
		cursor.close() 
		conn.close()
		#print(_hashdigest)
		print(account)
		print(_datos)
		#print(type(account))
		_nom=account[1]+' '+account[2]
		if account:
			if account[4]==1:
				access_token = jwt.encode({'id_usuario': _datos[0],'rol':_rol,'nombre':_nom, 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=12000)},SECRET_KEY,algorithm="HS256")
				respone = jsonify({'message':'Login Exitoso!','token': access_token })
				respone.status_code = 200
				return respone
			else:
				respone = jsonify({'message':'Usuario inactivo, contacta al administrador'})
				respone.status_code = 200
				return respone	
		else:
			respone =jsonify({'message':'Incorrect username/password!'})
			respone.status_code=302
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
def desing():
	key = RSA.importKey(open('test1.pem',"r").read())
	_n=key.n
	_e=key.e
	if request.method == 'POST':
		#
		_json = request.json
		_Element=_json['data']
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
def upload_csv():
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
		bindData=(str(_pregunta), str(_resp),str(_tipo), str(_materia))
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
