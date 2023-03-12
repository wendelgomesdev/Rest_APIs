from flask import Flask, render_template, redirect, url_for, jsonify, request, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import requests
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'

# Configurações básicas do Flask-WTF
app.config['WTF_CSRF_SECRET_KEY'] = 'mysecretkey'

# Formulário de login
class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Faz uma requisição à API de login
        api_url = 'http://localhost:5000/login'
        data = {'username': username, 'password': password}
        response = requests.post(api_url, json=data)

        # Verifica a resposta da API
        if response.status_code == 200:
            access_token = response.json().get('access_token')
            refresh_token = response.json().get('refresh_token')

            # Cria o cookie com o token de acesso e redireciona para a página de destino
            response = redirect(session['next'])
            print(session['next'])
            access_token_expires = 3600
            refresh_token_expires = datetime.now() + timedelta(days=30)
            response.set_cookie('access_token', access_token, secure=True, httponly=True, max_age=access_token_expires)
            response.set_cookie('refresh_token', refresh_token, secure=True, httponly=True, expires=refresh_token_expires)

            return response
    
    return render_template('login.html', form=form)

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        access_token = request.cookies.get('access_token')
        refresh_token = request.cookies.get('refresh_token')
        if access_token is None or refresh_token is None:
            # O usuário ainda não foi autenticado, redirecione para a página de login
            session['next'] = request.url
            return redirect(url_for('login'))
        
        api_url = 'http://localhost:5000/protected'
        headers = {'Authorization': 'Bearer ' + access_token}
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            # O usuário está autenticado, execute a rota original
            return func(*args, **kwargs)
        elif response.status_code == 401:
            # O token de acesso expirou, renove-o com o token de atualização
            api_url = 'http://localhost:5000/refresh'
            headers = {'Authorization': 'Bearer ' + refresh_token}
            response = requests.post(api_url, headers=headers)
            if response.status_code == 200:
                access_token = response.json().get('access_token')
                refresh_token = response.json().get('refresh_token')
                # Atualize os cookies com os novos tokens
                print(session['next'])
                response = redirect(request.url)
                access_token_expires = datetime.now() + timedelta(hours=1)
                refresh_token_expires = datetime.now() + timedelta(days=30)
                response.set_cookie('access_token', access_token, secure=True, httponly=True, expires=access_token_expires)
                response.set_cookie('refresh_token', refresh_token, secure=True, httponly=True, expires=refresh_token_expires)
                # Execute a rota original
                return func(*args, **kwargs)
            else:
                # O token de atualização também expirou, redirecione para a página de login
                session['next'] = request.url
                return redirect(url_for('login'))
        else:
            # Houve um erro desconhecido, redirecione para a página de login
            return redirect(url_for('login'))
    return decorated_function

# Rota protegida por autenticação com token JWT
@app.route('/painel', methods=['GET'])
@login_required
def painel():
    return f'<h1>Olá, usuário teste</h1>'

# Rota protegida por autenticação com token JWT
@app.route('/teste', methods=['GET'])
@login_required
def teste():
    return f'<h1>Olá, isso é um teste!</h1>'

if __name__ == '__main__':
    app.run(debug=True, port=8000)
