from flask_mail import Mail, Message

mail = Mail()

def send_otp_email(app, to_email, otp):
    try:
        with app.app_context():   # 🔥 VERY IMPORTANT
            msg = Message(
                subject="Private Vault OTP Verification",
                sender=app.config['MAIL_USERNAME'],
                recipients=[to_email]
            )
            msg.body = f"Your OTP is {otp}. It expires in 5 minutes."
            mail.send(msg)

            print("✅ OTP SENT:", otp)

    except Exception as e:
        print("❌ MAIL ERROR:", e)