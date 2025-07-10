from flask import Flask, render_template_string, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
import requests, os, uuid

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xtrabirg.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

NOWPAYMENTS_API = os.getenv("NOWPAYMENTS_API_KEY")

# Модели
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    balance_usdt = db.Column(db.Float, default=0)

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100))
    pair = db.Column(db.String(10))
    type = db.Column(db.String(10))  # buy/sell
    amount = db.Column(db.Float)
    price = db.Column(db.Float)

# Получение курса
def get_price(pair="bitcoin"):
    try:
        r = requests.get(f"https://api.coingecko.com/api/v3/simple/price?ids={pair}&vs_currencies=usd")
        return r.json()[pair]['usd']
    except:
        return 0

# Страницы
@app.route('/')
def index():
    if 'user' not in session:
        return redirect('/login')
    user = User.query.filter_by(email=session['user']).first()
    price_btc = get_price("bitcoin")
    return render_template_string(TEMPLATE, balance=user.balance_usdt, price_btc=price_btc, email=user.email)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        if User.query.filter_by(email=email).first():
            return "User exists"
        user = User(email=email, password=request.form['password'])
        db.session.add(user)
        db.session.commit()
        session['user'] = user.email
        return redirect('/')
    return render_template_string(REGISTER)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email'], password=request.form['password']).first()
        if user:
            session['user'] = user.email
            return redirect('/')
        return "Invalid"
    return render_template_string(LOGIN)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/buy', methods=['POST'])
def buy():
    if 'user' not in session:
        return redirect('/login')
    amount = float(request.form['amount'])
    price = get_price("bitcoin")
    cost = amount * price
    user = User.query.filter_by(email=session['user']).first()
    if user.balance_usdt >= cost:
        user.balance_usdt -= cost
        db.session.add(Trade(user=user.email, pair="BTC/USDT", type="buy", amount=amount, price=price))
        db.session.commit()
        return redirect('/')
    return "Not enough balance"

@app.route('/topup', methods=['GET'])
def topup():
    if 'user' not in session:
        return redirect('/login')
    payload = {
        "price_amount": 10,
        "price_currency": "usd",
        "pay_currency": "usdttrc20",
        "ipn_callback_url": "https://nowpayments.io",
        "order_id": str(uuid.uuid4()),
        "order_description": "XtraBirg Top-up",
    }
    headers = {"x-api-key": NOWPAYMENTS_API}
    res = requests.post("https://api.nowpayments.io/v1/invoice", json=payload, headers=headers)
    url = res.json().get("invoice_url", "/")
    return redirect(url)

@app.route('/api/balance')
def api_balance():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = User.query.filter_by(email=session['user']).first()
    return jsonify({"usdt": user.balance_usdt})

@socketio.on('message')
def handle_msg(msg):
    emit('message', msg, broadcast=True)

# Шаблоны HTML
TEMPLATE = """
<!DOCTYPE html><html><head>
<title>XtraBirg</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.3.2/socket.io.min.js"></script>
</head><body class="bg-gray-900 text-white">
<div class="p-4">
<h1 class="text-2xl">Добро пожаловать, {{email}}</h1>
<p class="my-2">Баланс: <b>{{balance}}</b> USDT</p>
<p>Цена BTC: <b>{{price_btc}}</b> USD</p>
<form action="/buy" method="post" class="my-4">
<input name="amount" placeholder="Сколько BTC?" class="p-2 text-black">
<button class="bg-green-500 px-4 py-2">Купить</button>
</form>
<a href="/topup" class="bg-blue-600 px-4 py-2">Пополнить баланс</a>
<a href="/logout" class="ml-4 text-red-400">Выйти</a>
</div>
<div class="fixed bottom-0 w-full bg-gray-800 p-2">
<h2>Чат:</h2>
<ul id="messages" class="text-sm"></ul>
<input id="msg" class="w-full p-1 text-black" placeholder="Сообщение...">
</div>
<script>
let socket = io();
document.getElementById("msg").addEventListener("keypress", e => {
  if (e.key === "Enter") {
    socket.send(e.target.value);
    e.target.value = "";
  }
});
socket.on("message", msg => {
  let li = document.createElement("li");
  li.textContent = msg;
  document.getElementById("messages").append(li);
});
</script>
</body></html>
"""

REGISTER = """<form method="post">
<h1>Регистрация</h1>
<input name="email" placeholder="Email"><br>
<input name="password" type="password" placeholder="Пароль"><br>
<button>Зарегистрироваться</button>
</form>"""

LOGIN = """<form method="post">
<h1>Вход</h1>
<input name="email" placeholder="Email"><br>
<input name="password" type="password" placeholder="Пароль"><br>
<button>Войти</button>
</form>"""

# Запуск
if __name__ == '__main__':
    db.create_all()
    socketio.run(app, host="0.0.0.0", port=5000)
