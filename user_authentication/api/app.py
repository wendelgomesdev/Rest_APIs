from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, create_refresh_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.user_agent import UserAgent
from datetime import timedelta
import redis

ACCESS_TOKEN_EXPIRES = timedelta(minutes=1)
REFRESH_TOKEN_EXPIRES = timedelta(days=30)
REVOKED_TOKEN_EXPIRES = timedelta(days=30)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'  # chave secreta para codificar o token JWT
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_TOKEN_EXPIRES  # tempo de expiração do token
jwt_manager = JWTManager(app)
security_redis  = redis.StrictRedis(host="localhost", port=6379, db=0, decode_responses=True)

# dicionário simulando um banco de dados de usuários
users = {
    'john': 'password1',
    'susan': 'password2',
    'bob': 'password3'
}

# rota de login para gerar um token JWT
@app.route('/login', methods=['POST'])
def login():
    user_agent = UserAgent(request.headers.get('User-Agent'))
    print(user_agent)
    

    username = request.json.get('username')
    password = request.json.get('password')
    
    print(username, password)

    # verificar se o usuário existe no dicionário de usuários
    if username in users and password == users[username]:
        access_token = create_access_token(identity=username, fresh=True)
        refresh_token = create_refresh_token(identity=username)
        
        # Adiciona o refresh token ao Redis
        security_redis.set(username, refresh_token, ex=REFRESH_TOKEN_EXPIRES)

        # Retorna o token para o cliente
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200

    return jsonify({'message': 'Invalid username or password'}), 401

# rota protegida que requer autenticação JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():

    current_user = get_jwt_identity()
    return jsonify({'message': current_user}), 200

# rota de logout que adiciona o token à blacklist
@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    security_redis.set(jti, '', ex=REVOKED_TOKEN_EXPIRES)

    current_user = get_jwt_identity()
    security_redis.delete(current_user)
    return jsonify({'message': 'Successfully logged out'}), 200

# função para verificar se o token está na blacklist
@jwt_manager.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_data):
    jti = jwt_data['jti']
    token_in_redis = security_redis.get(jti)
    if token_in_redis is not None:
        return True


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    #refresh_token = get_jwt()['refresh_token']
    print(current_user)
    # Verificar se o refresh token está presente no banco de dados
    if not security_redis.exists(current_user):
        return jsonify({'message': 'Refresh token is invalid'}), 401

    # Gerar novos tokens de acesso e de atualização
    new_access_token = create_access_token(identity=current_user, fresh=False)
    new_refresh_token = create_refresh_token(identity=current_user)

    # Adicionar o novo refresh token ao Redis
    security_redis.set(current_user, new_refresh_token, ex=REFRESH_TOKEN_EXPIRES)

    # Retornar os novos tokens para o cliente
    return jsonify(access_token=new_access_token, refresh_token=new_refresh_token), 200


if __name__ == '__main__':
    # Inicia o servidor Flask
    app.run(debug=True, port=5000)