from flask import Flask, render_template_string, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import requests, os, uuid, datetime

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xtrabirg.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)

NOWPAYMENTS_API = os.getenv("NOWPAYMENTS_API_KEY")
STRIPE_PUBKEY = os.getenv("STRIPE_PUBKEY", "")
STRIPE_SECRET = os.getenv("STRIPE_SECRET", "")

SUPPORTED_TOKENS = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "SOL": "solana",
    "DOGE": "dogecoin",
    "XTRA": "usd"
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(256))
    balances = db.Column(db.PickleType, default={})

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120))
    type = db.Column(db.String(50))
    token = db.Column(db.String(10))
    amount = db.Column(db.Float)
    price = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

def get_price(token):
    if token == "XTRA":
        return 1.0
    try:
        name = SUPPORTED_TOKENS[token]
        res = requests.get(f"https://api.coingecko.com/api/v3/simple/price?ids={name}&vs_currencies=usd")
        return res.json()[name]['usd']
    except:
        return 0.0

@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    password = request.form['password']
    if User.query.filter_by(email=email).first():
        return "Email already registered"
    user = User(email=email, password_hash=generate_password_hash(password))
    user.balances = {"USDT": 0.0, "BTC": 0.0, "ETH": 0.0, "SOL": 0.0, "DOGE": 0.0, "XTRA": 0.0}
    db.session.add(user)
    db.session.commit()
    session['user'] = email
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return "Invalid credentials"
    session['user'] = email
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/buy', methods=['POST'])
def buy():
    if 'user' not in session:
        return redirect('/')
    token = request.form['token']
    amount = float(request.form['amount'])
    user = User.query.filter_by(email=session['user']).first()
    price = get_price(token)
    total = amount * price
    if user.balances.get('USDT', 0) >= total:
        user.balances['USDT'] -= total
        user.balances[token] += amount
        db.session.add(Transaction(
            user_email=user.email,
            type="buy",
            token=token,
            amount=amount,
            price=price
        ))
        db.session.commit()
    return redirect('/')

@app.route('/deposit', methods=['POST'])
def deposit():
    if 'user' not in session:
        return redirect('/')
    amount = float(request.form['amount'])
    payload = {
        "price_amount": amount,
        "price_currency": "usd",
        "pay_currency": "usdttrc20",
        "ipn_callback_url": "https://nowpayments.io",
        "order_id": str(uuid.uuid4()),
        "order_description": f"Deposit for {session['user']}"
    }
    headers = {"x-api-key": NOWPAYMENTS_API}
    res = requests.post("https://api.nowpayments.io/v1/invoice", json=payload, headers=headers)
    invoice_url = res.json().get("invoice_url", "/")
    return redirect(invoice_url)

@app.route('/stripe', methods=['POST'])
def stripe():
    if 'user' not in session:
        return redirect('/')
    amount = int(float(request.form['amount']) * 100)
    stripe_session = requests.post(
        "https://api.stripe.com/v1/checkout/sessions",
        headers={
            "Authorization": f"Bearer {STRIPE_SECRET}",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data={
            "payment_method_types[]": "card",
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][product_data][name]": "USDT Balance Top-up",
            "line_items[0][price_data][unit_amount]": str(amount),
            "line_items[0][quantity]": "1",
            "mode": "payment",
            "success_url": "https://xtrabirg.onrender.com/success?amount=" + str(amount / 100),
            "cancel_url": "https://xtrabirg.onrender.com/"
        }
    )
    session_data = stripe_session.json()
    return redirect(session_data.get("url", "/"))

@app.route('/success')
def stripe_success():
    if 'user' not in session:
        return redirect('/')
    amount = float(request.args.get("amount", 0))
    user = User.query.filter_by(email=session['user']).first()
    user.balances['USDT'] += amount
    db.session.add(Transaction(
        user_email=user.email,
        type="deposit",
        token="USDT",
        amount=amount,
        price=1
    ))
    db.session.commit()
    return redirect('/')
@app.route('/history')
def history():
    if 'user' not in session:
        return redirect('/')
    txs = Transaction.query.filter_by(user_email=session['user']).order_by(Transaction.timestamp.desc()).all()
    return jsonify([{
        "type": tx.type,
        "token": tx.token,
        "amount": tx.amount,
        "price": tx.price,
        "time": tx.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    } for tx in txs])

@socketio.on('message')
def handle_message(data):
    emit('message', {
        'user': session.get('user', 'Гость'),
        'text': data
    }, broadcast=True)

@app.route('/')
def index():
    if 'user' not in session:
        return render_template_string('''
        <html class="dark"><head>
        <title>XtraBirg Login</title>
        <script src="https://cdn.tailwindcss.com"></script></head>
        <body class="bg-gray-900 text-white flex items-center justify-center h-screen">
        <div class="bg-gray-800 p-8 rounded-xl shadow-lg w-full max-w-md">
            <h1 class="text-2xl font-bold mb-4">XtraBirg Login</h1>
            <form action="/login" method="post" class="space-y-4">
                <input name="email" placeholder="Email" class="w-full p-2 rounded bg-gray-700">
                <input name="password" type="password" placeholder="Password" class="w-full p-2 rounded bg-gray-700">
                <button class="bg-blue-600 w-full py-2 rounded">Login</button>
            </form>
            <hr class="my-4 border-gray-600">
            <form action="/register" method="post" class="space-y-4">
                <input name="email" placeholder="Email" class="w-full p-2 rounded bg-gray-700">
                <input name="password" type="password" placeholder="Password" class="w-full p-2 rounded bg-gray-700">
                <button class="bg-green-600 w-full py-2 rounded">Register</button>
            </form>
        </div></body></html>
        ''')

    user = User.query.filter_by(email=session['user']).first()
    prices = {token: get_price(token) for token in SUPPORTED_TOKENS}
    return render_template_string('''
    <html class="dark"><head>
    <title>XtraBirg — Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.socket.io/4.3.2/socket.io.min.js"></script></head>
    <body class="bg-gray-900 text-white p-6">
    <div class="max-w-5xl mx-auto">
        <h1 class="text-3xl font-bold mb-4">Welcome, {{ user.email }}</h1>
        <a href="/logout" class="text-red-400 underline">Logout</a>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
            <div class="bg-gray-800 p-4 rounded-xl">
                <h2 class="text-xl font-semibold mb-2">💰 Your Balances</h2>
                <ul class="space-y-1">
                    {% for token, amount in user.balances.items() %}
                    <li>{{ token }}: {{ '%.4f'|format(amount) }}</li>
                    {% endfor %}
                </ul>
            </div>
            <div class="bg-gray-800 p-4 rounded-xl">
                <h2 class="text-xl font-semibold mb-2">📈 Prices</h2>
                <ul class="space-y-1">
                    {% for token, price in prices.items() %}
                    <li>{{ token }}: ${{ '%.2f'|format(price) }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
            <form action="/buy" method="post" class="bg-gray-800 p-4 rounded-xl space-y-2">
                <h2 class="text-xl font-semibold">🔁 Buy Tokens</h2>
                <select name="token" class="w-full p-2 bg-gray-700 rounded">
                    {% for token in prices.keys() %}
                    <option value="{{ token }}">{{ token }}</option>
                    {% endfor %}
                </select>
                <input name="amount" placeholder="Amount" class="w-full p-2 bg-gray-700 rounded">
                <button class="bg-blue-600 px-4 py-2 rounded w-full">Buy</button>
            </form>

            <form action="/deposit" method="post" class="bg-gray-800 p-4 rounded-xl space-y-2">
                <h2 class="text-xl font-semibold">📥 Deposit via NOWPayments</h2>
                <input name="amount" placeholder="USD Amount" class="w-full p-2 bg-gray-700 rounded">
                <button class="bg-green-600 px-4 py-2 rounded w-full">Deposit</button>
            </form>

            <form action="/stripe" method="post" class="bg-gray-800 p-4 rounded-xl space-y-2">
                <h2 class="text-xl font-semibold">💳 Deposit with Card (Stripe)</h2>
                <input name="amount" placeholder="USD Amount" class="w-full p-2 bg-gray-700 rounded">
                <button class="bg-yellow-600 px-4 py-2 rounded w-full">Pay</button>
            </form>

            <div class="bg-gray-800 p-4 rounded-xl">
                <h2 class="text-xl font-semibold">📜 History</h2>
                <ul id="history" class="space-y-1 text-sm"></ul>
            </div>
        </div>

        <div class="mt-6 bg-gray-800 p-4 rounded-xl">
            <h2 class="text-xl font-semibold mb-2">💬 Chat</h2>
            <div id="chat" class="h-40 overflow-y-scroll bg-gray-700 p-2 rounded mb-2"></div>
            <form id="chatForm">
                <input id="chatInput" placeholder="Type message..." class="w-full p-2 bg-gray-700 rounded">
            </form>
        </div>
    </div>

    <script>
    const socket = io();
    document.getElementById('chatForm').addEventListener('submit', e => {
        e.preventDefault();
        const msg = document.getElementById('chatInput').value;
        socket.emit('message', msg);
        document.getElementById('chatInput').value = '';
    });
    socket.on('message', data => {
        const chat = document.getElementById('chat');
        chat.innerHTML += `<div><b>${data.user}:</b> ${data.text}</div>`;
        chat.scrollTop = chat.scrollHeight;
    });
    fetch('/history').then(res => res.json()).then(data => {
        const h = document.getElementById('history');
        data.forEach(tx => {
            h.innerHTML += `<li>${tx.time}: ${tx.type} ${tx.amount} ${tx.token} @ $${tx.price}</li>`;
        });
    });
    </script>
    </body></html>
    ''', user=user, prices=prices)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
