import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import bcrypt
import ccxt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

CRYPTO_SYMBOLS = ['BTC', 'ETH', 'XRP', 'LTC', 'BCH', 'EOS', 'BNB', 'ADA', 'DOT', 'LINK']

def init_db():
    with sqlite3.connect('users.db') as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            );
        ''')
        db.commit()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            with sqlite3.connect('users.db') as db:
                cursor = db.cursor()
                cursor.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)', (username, hashed))
                db.commit()
            flash('You have successfully registered', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT id, username, hashed_password FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password, user[2]):
                session['loggedin'] = True
                session['user_id'] = user[0]
                session['username'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect username/password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password'].encode('utf-8')
        hashed = bcrypt.hashpw(new_password, bcrypt.gensalt())

        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            try:
                cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
                if cursor.fetchone() is not None:
                    cursor.execute('UPDATE users SET hashed_password = ? WHERE username = ?', (hashed, username))
                    db.commit()
                    flash('Password successfully updated', 'success')
                else:
                    flash('Username not found', 'danger')
            except sqlite3.Error as error:
                flash('Error while updating password', 'danger')

        return redirect(url_for('login'))

    return render_template('reset.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def main_page():
    selected_exchanges = ['binance', 'kraken', 'coinbasepro', 'bitfinex']
    crypto_symbol = 'BTC'

    if request.method == 'POST':
        selected_exchanges = request.form.getlist('exchanges')
        crypto_symbols_input = request.form.get('crypto_symbol', default='')
        crypto_symbols = [symbol.strip().upper() for symbol in crypto_symbols_input.split(',')]
        
        all_prices = {symbol: fetch_crypto_prices(selected_exchanges, symbol) for symbol in crypto_symbols}
    else:
        all_prices = {crypto_symbol: fetch_crypto_prices(selected_exchanges, crypto_symbol)}

    return render_template('main.html', exchanges=selected_exchanges, prices=all_prices, crypto_symbols=CRYPTO_SYMBOLS, selected_symbol=crypto_symbol)


def fetch_crypto_prices(exchanges, symbol):
    prices = {}
    for exchange_id in exchanges:
        exchange_class = getattr(ccxt, exchange_id)()
        try:
            exchange_class.load_markets()
            market_pair = symbol + '/USDT' 
            price = exchange_class.fetch_ticker(market_pair)['last']
            prices[exchange_id] = f'${price:.2f}'
        except Exception as e:
            print(f"Error fetching price for {symbol} on {exchange_id}: {e}")  
            prices[exchange_id] = '---'
    return prices


@app.route('/prices')
def prices():
    selected_exchanges = request.args.getlist('exchanges')
    crypto_symbols = request.args.get('crypto_symbol').split(',')
    all_prices = {}

    for symbol in crypto_symbols:
        symbol_prices = fetch_crypto_prices(selected_exchanges, symbol.strip().upper())
        all_prices[symbol] = symbol_prices

    return jsonify(all_prices)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
