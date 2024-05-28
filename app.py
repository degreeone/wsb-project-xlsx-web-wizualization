from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import pandas as pd
import numpy as np
import io
import base64
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg') # Agg, to nieinteraktywny backend, który może tylko zapisywać do plików. 


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.anonymous_user = AnonymousUserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    data_analysis = relationship('DataAnalysis', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class DataAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    column_name = db.Column(db.String(80))
    value_counts = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    return redirect('/base')

@app.route('/base')
def base():
    return render_template('base.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Niepoprawny login lub hasło')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Podany adres e-mail jest już zarejestrowany.')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Konto zarejestrowane pomyślnie.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    try:
        data = pd.read_excel('data/ceny_towarów_i_usług konsumpcyjnych.xlsx', skiprows=10, usecols=range(51))
        data = data.head(62)
        data_shaping = data.drop('Jednostka', axis=1)
        
        products = data_shaping['Wskaźnik'].unique() # Wybieram unikalne wartości (produkty i usługi) z kolumny Wskaźnik (pierwsza kolumna)
        min_year = data_shaping.columns[1]  # Ustawiam zmienną min_year, która wybiera rok początkowy do zakresu i jest drugą kolumną w danych
        max_year = data_shaping.columns[-1]  # Ustawiam zmienną max_year, która wybiera rok końcowy do zakresu i jest ostatnią kolumną w danych
        
        data_shaping.loc[:, min_year:max_year] = data_shaping.loc[:, min_year:max_year].apply(lambda x: x.str.replace(',', '.'))
        data_shaping.loc[:, min_year:max_year] = data_shaping.loc[:, min_year:max_year].apply(pd.to_numeric, errors='coerce')
        analysis = data_shaping
        
    except Exception as e:
        flash(f'Błąd przy wczytywaniu danych: {e}')
        return redirect(url_for('dashboard', redirected='true')) # Przy jakichkolwiek błędach odczytu ustawiam redirected na wartość true
    
    if request.method == 'POST':
        product = request.form['product'] # Użytkownik wybiera z listy produktów i usług co chce wyświetlać (metodą POST w dashboard)
        start_year = int(request.form['start_year'])
        end_year = int(request.form['end_year'])
        
        if start_year > end_year:
            flash('Rok początkowy nie może być większy niż rok końcowy.')
            return redirect(url_for('dashboard'))
        
        if end_year > int(max_year):
            flash('Wybrany rok końcowy przekracza dostępne dane.')
            return redirect(url_for('dashboard'))
        
        selected_columns = [str(year) for year in range(start_year, end_year + 1)]
        analysis = analysis.loc[analysis['Wskaźnik'] == product, selected_columns]
        
        plot_url = create_plot_url(analysis, product)
        return render_template('dashboard.html', plot_url=plot_url, products=products, min_year=min_year, max_year=max_year, 
                       selected_product=product, selected_start_year=start_year, selected_end_year=end_year, analysis=analysis)

    return render_template('dashboard.html', products=products, min_year=min_year, max_year=max_year)

def create_plot_url(analysis, product):
    # Konwertuję DataFrame do tablicyNumPy
    array = analysis.values

    # Pobieram nazwy kolumn na etykiety osi x
    columns = analysis.columns.tolist()

    # Tworzę wykres na podstawie tablicy NumPy
    fig, ax = plt.subplots(figsize=(18, 8))
    for row in array:
        ax.plot(row)

    # Ustawiam etykiety osi x
    ax.set_xticks(range(len(columns)))
    ax.set_xticklabels(columns, rotation=90)

    # Ustawiam etykietę osi y
    ax.set_ylabel(product)

    # Zapisuję wykres do bufora w formacie PNG, a następnie ustawiam wskażnik bufora na początek
    buf = io.BytesIO()
    fig.savefig(buf, format='png')
    buf.seek(0)

    # Koduję obraz w formacie base64
    plot_bytes = buf.read()
    plot_base64 = base64.b64encode(plot_bytes).decode()

    # Zwracam obraz w formacie base64 jako ciąg znaków (string)
    return f"data:image/png;base64,{plot_base64}"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)