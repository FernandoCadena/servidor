import pymysql
import json
from app import app
from config import mysql
from flask import jsonify
from flask import flash, request
import hashlib


###TEST####
#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1/login' --data '{"username":"a@b.c","password":"test"}'
@app.route('/login-test', methods=['GET', 'POST'])
def test_login():
	if request.method == 'POST':
		# Create variables for easy access
		_json = request.json
		_user=_json['_correo']
		_pass=_json['_password']
		_hash=hashlib.sha512()
		_hash.update(_pass.encode())
		_hashdigest=str(_hash.hexdigest())
		conn = mysql.connect()
		cursor = conn.cursor()
		cursor.execute('SELECT * FROM usuario WHERE correo = %s AND password = %s', (_user, _hashdigest,))
		account = cursor.fetchone()
		if account:
			cursor.execute('SELECT id_usuario, nombre, apellidos, role FROM usuario WHERE correo= %s',(_user))
			_info = cursor.fetchone()
			respone = jsonify(_info)
			respone.status_code = 200
			return respone
		else:
			respone =jsonify('Incorrect username/password!')
			respone.status_code=302
			return respone
	cursor.close() 
	conn.close()
####

@app.route('/csv', methods=['POST'])
def test():
	_json = request.json
	for i in range(1,len(_json['data'])-1):
		_temp=(_json['data'])[i]
		_dicc= (_temp['data'])
		_pregunta = _dicc[0]
		_opa = _dicc[1]
		_opb = _dicc[2]
		_opc = _dicc[3]
		_opd = _dicc[4]
		_resp = _dicc[5]
		_nivel = _dicc[6]
		_materia = _dicc[7]
		sqlQuery = "INSERT INTO reactivo_opm(pregunta, op1, op2, op3, op4, op_correcta, nivel, materia) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)"
		bindData=(str(_pregunta), str(_opa), str(_opb), str(_opc), str(_opd), _resp, _nivel, str(_materia))
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		cursor.execute(sqlQuery, bindData)
		conn.commit()
	respone = jsonify('Reactivos cargados con Exito!')
	respone.status_code = 200
	cursor.close() 
	conn.close()
	return respone
	

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


#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1/add' --data '{"id_usuario":"102","nombre":"Fernando","apellidos":"cadena m","correo":"a@b.c","password":"test","role":"1"}'
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
		_role = _json['role']
		_hash=hashlib.sha512()
		_hash.update(_pass.encode())
		_hashdigest=str(_hash.hexdigest())
		print (_hashdigest)
		if _id and _nombre and _apellidos and _correo and _pass and _role and request.method == 'POST':
			sqlQuery = "INSERT INTO usuario VALUES(%s, %s, %s, %s, %s, %s)"
			bindData=(str(_id), str(_nombre), str(_apellidos), str(_correo), str(_hashdigest), str(_role))
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute(sqlQuery, bindData)
			conn.commit()
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


#curl -X GET -i 'http://127.0.0.1:5000/profile?id=test'
@app.route('/profile')
def emp():
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
def add_eval():
	try:
		_json = request.json
		print (_json)
		#_id = _json['id_eval']
		_id_user = _json['id_usuario']
		_materia = _json['materia']
		_fecha = _json['date']
		_tipo = _json['tipo']
		_ids_reactivos = _json['ids_reactivos']
		_titulo_eval=_json['nombre_eval']
		_estado=_json['estado']
		_reactivos=''
		_temp=''
		for i in range(len(_ids_reactivos)):
			_temp+=_ids_reactivos[i]['id']
			_temp+=','
		_reactivos=_temp[:-1]
		if _id_user and _materia and _fecha and _tipo and _ids_reactivos and _titulo_eval and _estado and request.method == 'POST':
			sqlQuery = "INSERT INTO evaluacion(id_usuario, materia, fecha, tipo, ids_raectivos, titulo_eval, estado) VALUES(%s, %s, %s, %s, %s, %s, %s)"
			bindData=(str(_id_user), str(_materia), str(_fecha), str(_tipo), str(_reactivos), str(_titulo_eval), str(_estado))
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute(sqlQuery, bindData)
			conn.commit()
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
def filtro_reactivos():
	_materia=request.args.get('materia')#"test"
	_nivel=request.args.get('nivel')
	if(_materia):
		try:
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT id_reactivo, pregunta, op1, op2, op3, op4, nivel, materia FROM reactivo_opm WHERE materia=%s",_materia)
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

@app.route('/usr')
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
#curl -X GET -i 'http://localhost/quiz?eval=1'
@app.route('/quiz')
def obten_quiz():
	_quiz=request.args.get('eval')#"test"
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		cursor.execute("SELECT ids_reactivos FROM evaluacion WHERE id_eval=%s",_quiz)
		empRows = cursor.fetchone()
		reactivos= empRows["ids_reactivos"].split(',')
		print (reactivos[0])
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		_reactivos=[{"none":"none"}]
		for i in range(len(reactivos)):
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT pregunta, op1, op2, op3, op4 FROM reactivo_opm WHERE id_reactivo=%s",str(reactivos[i]))
			_reactivos.append(cursor.fetchone())
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
def calif_eval():
	try:
		conn = mysql.connect()
		cursor = conn.cursor(pymysql.cursors.DictCursor)
		_json = request.json
		print (_json)
		_id_eval = _json['id_eval']
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
			return not_found()
	except Exception as e:
		print(e)
	finally:
		cursor.close() 
		conn.close()



@app.route('/update', methods=['PUT'])
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

#curl -X POST -H 'Content-Type: application/json' -i 'http://127.0.0.1/login' --data '{"username":"a@b.c","password":"test"}'
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		# Create variables for easy access
		_json = request.json
		_user=_json['username']
		_pass=_json['password']
		_hash=hashlib.sha512()
		_hash.update(_pass.encode())
		_hashdigest=str(_hash.hexdigest())
		conn = mysql.connect()
		cursor = conn.cursor()
		cursor.execute('SELECT * FROM usuario WHERE correo = %s AND password = %s', (_user, _hashdigest,))
		account = cursor.fetchone()
		if account:
			respone = jsonify('Login Exitoso!')
			respone.status_code = 200
			return respone
		else:
			respone =jsonify('Incorrect username/password!')
			respone.status_code=302
			return respone
	cursor.close() 
	conn.close()



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
    app.run(debug=False,port=80)