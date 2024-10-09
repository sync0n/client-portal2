import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from botocore.exceptions import ClientError
import json
from cryptography.fernet import Fernet

def get_flask_secret_key():
    secret_name = "prod/flask_secret_key"
    region_name = "eu-central-1"

    # Create a Secrets Manager client
    session_aws = boto3.session.Session()
    client = session_aws.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print(f"Error retrieving Flask secret key from Secrets Manager: {e}")
        return None
    else:
        secret = get_secret_value_response['SecretString']

        try:
            # Attempt to parse the secret as JSON (in case it's stored as a JSON object)
            secret_dict = json.loads(secret)
            return secret_dict.get('FLASK_SECRET_KEY')
        except json.JSONDecodeError:
            # If the secret is not JSON, return the raw string
            return secret  # Assuming the secret itself is the key


app = Flask(__name__)

flask_secret_key = get_flask_secret_key()

if flask_secret_key:
    app.secret_key = flask_secret_key
else:
    print("Flask secret key not found. Exiting.")
    exit(1)


# Ensure the instance folder exists
if not os.path.exists(app.instance_path):
    os.makedirs(app.instance_path)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'users.db')
db = SQLAlchemy(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def get_encryption_key():
    secret_name = "prod/encryption_key_3"  # Replace with your actual secret name
    region_name = "eu-central-1"         # Replace with your AWS region

    # Create a Secrets Manager client
    session_aws = boto3.session.Session()
    client = session_aws.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print(f"Error retrieving encryption key from Secrets Manager: {e}")
        return None
    else:
        # Secrets Manager returns the secret as a string
        secret = get_secret_value_response['SecretString']
        # The secret is assumed to be the encryption key
        return secret

# Get the encryption key from AWS Secrets Manager
encryption_key = get_encryption_key()
if encryption_key:
    app.config['ENCRYPTION_KEY'] = encryption_key.encode()
else:
    # Handle error (e.g., exit application or generate a key for testing)
    print("Encryption key not found. Exiting.")
    exit(1)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=True)  # Portal password
    used_thingsboard_password = db.Column(db.Boolean, default=False)  # Flag to track if ThingsBoard password has been used
    customerId = db.Column(db.String(150))  # Store ThingsBoard customerId
    roles = db.Column(db.Text)  # Store JSON-encoded list of roles
    tb_token = db.Column(db.String(500))  # Store ThingsBoard token for each user
    tb_password_encrypted = db.Column(db.String(500))  # Encrypted ThingsBoard password

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        print(f"Set password for user {self.username}")

    def check_password(self, password):
        result = check_password_hash(self.password_hash, password)
        print(f"Password check for user {self.username}: {result}")
        return result

    def set_tb_password(self, tb_password):
        cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])
        encrypted_password = cipher_suite.encrypt(tb_password.encode())
        self.tb_password_encrypted = encrypted_password.decode()
        print(f"Set encrypted ThingsBoard password for user {self.username}")

    def get_tb_password(self):
        cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])
        decrypted_password = cipher_suite.decrypt(self.tb_password_encrypted.encode())
        return decrypted_password.decode()

    def set_roles(self, roles_list):
        self.roles = json.dumps(roles_list)

    def get_roles(self):
        return json.loads(self.roles) if self.roles else []

@login_manager.user_loader
def load_user(user_id):
    try:
        user = User.query.get(int(user_id))
        print(f"Loaded user from user_loader: {user}")
        return user
    except ValueError:
        print(f"ValueError in user_loader with user_id: {user_id}")
        return None

# Utility functions
def check_user_in_thingsboard(email, tenant_token):
    url = f"http://3.79.179.54:8080/api/v1/accounts?email={email}"
    #url = f"http://10.0.5.16:8080/api/v1/accounts?email={email}"

    headers = {"Authorization": f"Bearer {tenant_token}"}
    print(f"Checking user in ThingsBoard: {email}")
    print(f"GET {url} with headers {headers}")
    response = requests.get(url, headers=headers)
    print(f"Response from ThingsBoard user check: {response.status_code}, {response.text}")
    if response.status_code == 200:
        return response.json()  # User exists in ThingsBoard
    return None  # User doesn't exist

def create_user_in_portal(email, roles, customerId):
    print(f"Creating user in portal: {email}, roles: {roles}, customerId: {customerId}")
    new_user = User(username=email, customerId=customerId)
    new_user.set_roles(roles)  # Store all roles
    db.session.add(new_user)
    db.session.commit()
    print(f"User {email} created in local database.")

def get_tenant_credentials():
    secret_name = "prod/tenant_credentials"  # Replace with your actual secret name
    region_name = "eu-central-1"  # Replace with your AWS region

    # Create a Secrets Manager client
    session_aws = boto3.session.Session()
    client = session_aws.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print(f"Error retrieving secret: {e}")
        return None, None
    else:
        # Secrets Manager returns the secret as a string
        secret = get_secret_value_response['SecretString']
        # Convert the secret string to a dictionary
        secret_dict = json.loads(secret)
        username = secret_dict.get('TENANT_USERNAME')
        password = secret_dict.get('TENANT_PASSWORD')
        return username, password

def get_tenant_token():
    url = "https://thingsboard.noranet-infra.net/api/auth/login"
    username, password = get_tenant_credentials()

    if not username or not password:
        print("Tenant credentials not found.")
        return None

    data = {"username": username, "password": password}
    print(f"Requesting tenant token from ThingsBoard with URL: {url}")
    response = requests.post(url, json=data)
    print(f"Response from ThingsBoard tenant token request: {response.status_code}, {response.text}")
    if response.status_code == 200:
        token = response.json().get('token')
        print(f"Tenant token received.")
        return token
    print("Failed to get tenant token from ThingsBoard.")
    return None

def get_user_dashboards(customerId, tenant_token):
    url = f"https://thingsboard.noranet-infra.net/api/customer/{customerId}/dashboards?pageSize=10&page=0"
    headers = {"Authorization": f"Bearer {tenant_token}"}
    print(f"Getting dashboards for customerId: {customerId}")
    print(f"GET {url} with headers {headers}")
    response = requests.get(url, headers=headers)
    print(f"Response from ThingsBoard dashboard request: {response.status_code}, {response.text}")
    if response.status_code == 200:
        return response.json()  # List of dashboards
    print("Failed to retrieve dashboards from ThingsBoard.")
    return None  # Failed to retrieve dashboards

def store_token_in_db(user, token):
    user.tb_token = token
    db.session.commit()
    print(f"Stored ThingsBoard token for user {user.username} in the database.")

def get_user_token(username, password):
    url = "https://thingsboard.noranet-infra.net/api/auth/login"
    data = {"username": username, "password": password}
    print(f"Requesting user token from ThingsBoard for user {username}")
    response = requests.post(url, json=data)
    print(f"Response from ThingsBoard user token request: {response.status_code}, {response.text}")
    if response.status_code == 200:
        token = response.json().get('token')
        print(f"User token received for {username}")
        return token
    print(f"Failed to get user token for {username} from ThingsBoard.")
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login route called with method:", request.method)
    
    if request.method == 'GET':
        return render_template('login.html')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"Login attempt for username: {username}")

        user = User.query.filter_by(username=username).first()

        if user:
            if user.password_hash:
                # User has a portal password set
                if user.check_password(password):
                    print("Portal password correct, logging in user.")
                    login_user(user)
                    session.permanent = True

                    # Use stored ThingsBoard password to get user token
                    tb_password = user.get_tb_password()
                    user_token = get_user_token(username, tb_password)
                    if user_token:
                        store_token_in_db(user, user_token)
                    else:
                        flash('Failed to authenticate with ThingsBoard.')
                        return redirect(url_for('login'))

                    return redirect(url_for('home'))
                else:
                    # Portal password is incorrect
                    flash('Incorrect password. Please try again.')
                    return redirect(url_for('login'))
            else:
                # User exists but hasn't set a portal password yet
                # Authenticate with ThingsBoard using the provided password
                user_token = get_user_token(username, password)
                if user_token:
                    login_user(user)
                    store_token_in_db(user, user_token)

                    # Save ThingsBoard password
                    user.set_tb_password(password)
                    user.used_thingsboard_password = True
                    db.session.commit()

                    print("Redirecting to create new password since ThingsBoard password was used.")
                    return redirect(url_for('create_new_password'))
                else:
                    flash('Incorrect ThingsBoard password. Please try again.')
                    return redirect(url_for('login'))

        else:
            # User not found in portal database
            # Attempt ThingsBoard authentication
            user_token = get_user_token(username, password)
            if user_token:
                # Get tenant token to check user in ThingsBoard
                tenant_token = get_tenant_token()
                if tenant_token:
                    tb_user_data = check_user_in_thingsboard(username, tenant_token)
                    if tb_user_data:
                        # Extract all roles associated with the user
                        roles = [user['role'] for user in tb_user_data if user['email'] == username]
                        roles = list(set(roles))  # Remove duplicates if any
                        customerId = tb_user_data[0]['customerId']  # Assuming customerId is the same
                        # Create user in portal database
                        create_user_in_portal(username, roles, customerId)
                        user = User.query.filter_by(username=username).first()
                        login_user(user)
                        store_token_in_db(user, user_token)

                        # Save ThingsBoard password
                        user.set_tb_password(password)
                        user.used_thingsboard_password = True
                        db.session.commit()

                        print("Redirecting to create new password since ThingsBoard password was used.")
                        return redirect(url_for('create_new_password'))
                    else:
                        flash('Failed to retrieve user data from ThingsBoard.')
                        return redirect(url_for('login'))
                else:
                    flash('Failed to authenticate with ThingsBoard.')
                    return redirect(url_for('login'))
            else:
                flash('Login failed. Please check your credentials.')
                return redirect(url_for('login'))

@app.route('/create_new_password', methods=['GET', 'POST'])
@login_required
def create_new_password():
    print(f"create_new_password route called with method: {request.method}")
    if request.method == 'POST':
        print("Received POST request to create_new_password")
        new_password = request.form.get('new_password')
        print(f"New password received: {new_password}")

        if new_password:
            current_user.set_password(new_password)
            current_user.used_thingsboard_password = False  # Update the flag
            db.session.commit()

            flash("Password updated successfully", "success")
            return redirect(url_for('home'))
        else:
            flash("Please enter a valid password", "error")

    return render_template('create_new_password.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/')
@login_required
def home():

    if current_user.used_thingsboard_password:
        print(f"Redirecting user {current_user.username} to create new password page.")
        return redirect(url_for('create_new_password'))

    customer_id = current_user.customerId
    tb_token = current_user.tb_token

    if not tb_token:
        flash('Access token missing. Please log in again.')
        return redirect(url_for('login'))

    # Get tenant token to retrieve dashboards
    tenant_token = get_tenant_token()
    if not tenant_token:
        flash('Failed to retrieve dashboards.')
        return redirect(url_for('home'))

    # Normalize user roles to lowercase
    user_roles = [role.lower() for role in current_user.get_roles()]
    print(f"User roles: {user_roles}")

    # Define the role to group mappings
    role_group_mapping = {
        'household_member': ['apartment'],
        'accountant': ['accountant'],
        'house_association_member': ['house association'],
        'board_member': ['house association', 'apartment'],  # Adjust as needed
        # Add other roles and their corresponding group names here
    }

    # Get the groups the user is allowed to access
    allowed_groups = set()
    for role in user_roles:
        groups_for_role = role_group_mapping.get(role, [])
        allowed_groups.update(groups_for_role)
        print(f"Role '{role}' maps to groups: {groups_for_role}")

    print(f"Allowed groups for user: {list(allowed_groups)}")

    # Define the mapping of dashboard names to image filenames
    dashboard_image_mapping = {
        'Accountant Dashboard': 'accountaint.jpg',
        'Apartment Dashboard': 'appartment.jpg',
        # Add more mappings as needed
    }

    dashboards = get_user_dashboards(customer_id, tenant_token)
    dashboard_links = []

    if dashboards and 'data' in dashboards:
        for dashboard in dashboards['data']:
            # Normalize group names to lowercase
            group_names = [group['name'].lower() for group in dashboard.get('groups', [])]
            print(f"Dashboard '{dashboard.get('name')}' groups: {group_names}")
            # Check if any of the dashboard's groups are in the allowed groups
            if any(group in allowed_groups for group in group_names):
                print(f"Adding dashboard '{dashboard.get('name')}' to dashboard_links")
                dashboard_id = dashboard['id']['id']
                dashboard_name = dashboard.get('name', 'Unnamed Dashboard')
                dashboard_url = f"https://thingsboard.noranet-infra.net/dashboard/{dashboard_id}?accessToken={tb_token}"

                # Get the image filename based on the dashboard name
                image_filename = dashboard_image_mapping.get(dashboard_name, 'default.jpg')  # Use default if not found
                image_url = url_for('static', filename=f'images/{image_filename}')

                dashboard_links.append({
                    'name': dashboard_name,
                    'url': dashboard_url,
                    'image': image_url
                })
            else:
                print(f"Dashboard '{dashboard.get('name')}' not added. No matching groups.")

    return render_template('index.html', dashboard_links=dashboard_links)

@app.route('/logout')
@login_required
def logout():
    print(f"User {current_user.username} logging out.")
    logout_user()
    print("User logged out.")
    return redirect(url_for('login'))

# Remaining routes for other views
@app.route('/alarm_settings')
@login_required
def alarm_settings():
    return render_template('alarm_settings.html')

@app.route('/guest_users')
@login_required
def guest_users():
    return render_template('guest_users.html')

@app.route('/housing_association')
@login_required
def housing_association():
    return render_template('housing_association.html')

@app.route('/integrations')
@login_required
def integrations():
    return render_template('integrations.html')

@app.route('/poa_credentials')
@login_required
def poa_credentials():
    return render_template('poa_credentials.html')

@app.route('/user_data')
@login_required
def user_data():
    return render_template('user_data.html')

@app.route('/thingsboard_login', methods=['POST'])
def thingsboard_login():
    data = request.get_json()
    tb_username = data.get('username')
    tb_password = data.get('password')
    print(f"ThingsBoard login attempt for username: {tb_username}")
    
    thingsboard_url = 'https://thingsboard.noranet-infra.net/api/auth/login'
    tb_response = requests.post(thingsboard_url, json={'username': tb_username, 'password': tb_password})
    print(f"Response from ThingsBoard login: {tb_response.status_code}, {tb_response.text}")

    if tb_response.status_code == 200:
        tb_tokens = tb_response.json()
        session['tb_token'] = tb_tokens.get('token')
        session['tb_refresh_token'] = tb_tokens.get('refreshToken')
        print(f'ThingsBoard login successful, token: {session["tb_token"]}')
        return jsonify({'status': 'success'}), 200
    else:
        print(f'ThingsBoard login failed, status code: {tb_response.status_code}')
        return jsonify({'status': 'failed'}), 401

@app.route('/test_auth')
@login_required
def test_auth():
    return "You are logged in!", 200

@login_manager.unauthorized_handler
def unauthorized_callback():
    print("Unauthorized access attempted.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        # Ensure the instance folder exists
        if not os.path.exists(app.instance_path):
            os.makedirs(app.instance_path, exist_ok=True)

        # Ensure the database and tables are created
        db.create_all()
        print("Ensured that the database and all tables are created.")

    app.run(debug=True, host='0.0.0.0')  # Listen on all interfaces