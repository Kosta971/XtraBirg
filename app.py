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
STRIPE_PUBKEY = os.getenv("STRIPE_PUBKEY")
STRIPE_SECRET = os.getenv("STRIPE_SECRET")

SUPPORTED_TOKENS = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "SOL": "solana",
    "DOGE": "dogecoin",
    "XTRA": "usd"  # фейковый токен, цена = 1
}

# Модели
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(256))
    balances = db.Column(db.PickleType, default={})  # {'BTC': 0.1, 'ETH': 0.0, 'USDT': 100}

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120))
    type = db.Column(db.String(50))  # deposit, buy
    token = db.Column(db.String(10))
    amount = db.Column(db.Float)
    price = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Курсы токенов
def get_price(token):
    if token == "XTRA":
        return 1.0
    try:
        name = SUPPORTED_TOKENS[token]
        res = requests.get(f"https://api.coingecko.com/api/v3/simple/price?ids={name}&vs_currencies=usd")
        return res.json()[name]['usd']
    except:
        return 0
