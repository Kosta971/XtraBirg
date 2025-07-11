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
