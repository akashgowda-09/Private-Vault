from flask import Flask, render_template
from config import Config
from utils.mail import mail

import utils.cloudinary_config

from routes.auth import auth
from routes.dashboard import dashboard
from routes.file import file_bp

app = Flask(__name__)
app.config.from_object(Config)

# ✅ SESSION FIX
app.secret_key = "supersecretkey"
app.config["SESSION_PERMANENT"] = True

@app.route("/")
def home():
    return render_template("welcome.html")

mail.init_app(app)

app.register_blueprint(auth)
app.register_blueprint(dashboard)
app.register_blueprint(file_bp)

if __name__ == "__main__":
    app.run(debug=True)