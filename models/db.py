from pymongo import MongoClient
from config import Config

client = MongoClient(Config.MONGO_URI)
db = client.get_database()   # IMPORTANT for Atlas
files = db["files"]
users = db["users"]
shares = db["shares"]
otp_collection = db["otp"]
