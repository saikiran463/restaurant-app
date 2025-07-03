from flask import Flask
from app.routes import routes


app = Flask(__name__, template_folder='app/templates')
app.secret_key = 'b7f8e2c1-4a9d-4e2a-8c3d-7f6e5a1b2c9d-!@#QWErty1234567890$%^&*()_+zxcvBNM<>?~'  # Strong random value for production
app.register_blueprint(routes)

if __name__ == '__main__':
# For development only. In production, use: gunicorn --bind 0.0.0.0:8000 run:app
    app.run(host='127.0.0.1', port=5000, debug=False)


