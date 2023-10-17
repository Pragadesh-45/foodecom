# Import necessary libraries
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson import ObjectId
from flask_bcrypt import Bcrypt
import os  # Import the os module
from flask_cors import CORS  # Import CORS

# Load environment variables from the .env file
from dotenv import load_dotenv
load_dotenv()

# Create a Flask web application
app = Flask(__name__)

CORS(app)  # Enable CORS for all routes

# Initialize Flask-Bcrypt for password hashing
bcrypt = Bcrypt(app)

# MongoDB configuration
# Use the environment variable to get the MongoDB URI
mongodb_uri = os.getenv("MONGODB_URI")
client = MongoClient(mongodb_uri)  # Use the URI from the environment variable
db = client["users"]
users_collection = db["users"]
user_data_collection = db["user_data"]


# Define a route for the homepage
@app.route('/')
def index():
    return "Welcome to User API"

# User Registration and Login endpoints

# Endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    # Extract user data from the request
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    confirm_password = request.json.get('confirm_password')
    
    # Check if any of the required fields are missing
    if not (username and email and password and confirm_password):
        return jsonify({'message': 'All fields are required'}), 400

    # Check if the user with the provided email already exists
    existing_user = users_collection.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'User with this email already exists'}), 400

    # Check if the password and confirm_password match
    if password != confirm_password:
        return jsonify({'message': 'Password and confirm password do not match'}), 400

    # Hash the user's password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    # Create a dictionary with user data
    user_data = {
        'username': username,
        'email': email,
        'password': hashed_password,
    }

    # Insert the user data into the database
    user_id = users_collection.insert_one(user_data).inserted_id

    return jsonify({'message': 'User registered successfully', 'user_id': str(user_id)}), 201

# Endpoint for user login
@app.route('/login', methods=['POST'])
def login():
    # Extract email and password from the request
    email = request.json['email']
    password = request.json['password']

    # Find the user with the provided email
    user = users_collection.find_one({'email': email})

    # Check if the user exists and the password is correct
    if user and bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401


# Run the Flask app if this script is executed
if __name__ == '__main__':
    app.run(debug=True)
