import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import pdfkit
from functools import wraps
from flask import make_response 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user



app = Flask(__name__)

# Configuration
app.secret_key = '0025a23d0211a298a258ce24b6456f01bee1ee63cc37c0b5109e122802068935'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'digital_class_journal'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # This makes results return as dictionaries
# Configure upload folder
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
mysql = MySQL(app)

# Flask-Login Setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        """
        Initialize user with dictionary containing:
        - id
        - name
        - email 
        - role
        - password (optional)
        """
        self.id = user_data.get('id')
        self.name = user_data.get('name')
        self.email = user_data.get('email')
        self.role = user_data.get('role')
        
        # Password is stored but not used by Flask-Login
        self.password = user_data.get('password')  

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, email, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(user)
    return None

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.close()
        
        if user_data and check_password_hash(user_data['password'], password):
            # Create user object without password
            user_obj = User({
                'id': user_data['id'],
                'name': user_data['name'],
                'email': user_data['email'],
                'role': user_data['role']
            })
            login_user(user_obj)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()  # Normalize email
        role = request.form.get('role')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate required fields
        if not all([name, email, role, password, confirm_password]):
            flash('Please fill all fields', 'danger')
            return render_template('register.html',
                                name=name,
                                email=email,
                                role=role)
        
        # Password confirmation check
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html',
                                name=name,
                                email=email,
                                role=role)
        
        # Check password strength
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return render_template('register.html',
                                name=name,
                                email=email,
                                role=role)
        
        cur = mysql.connection.cursor()
        try:
            # Check if email exists
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash('Email already registered', 'danger')
                # Return only name and role (not email)
                return render_template('register.html',
                                    name=name,
                                    role=role)
            
            # Hash password
            hashed_password = generate_password_hash(password)
            
            # Create new user
            cur.execute(
                "INSERT INTO users (name, email, role, password) VALUES (%s, %s, %s, %s)",
                (name, email, role, hashed_password)
            )
            mysql.connection.commit()
            
            # Get new user ID
            user_id = cur.lastrowid
            
            # Create User object and log in
            user_obj = User({
                'id': user_id,
                'name': name,
                'email': email,
                'role': role
            })
            login_user(user_obj)
            
            flash('Registration successful!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash('Registration failed. Please try again.', 'danger')
            return render_template('register.html',
                                name=name,
                                role=role)
        finally:
            cur.close()
    
    # GET request - show empty form
    return render_template('register.html')
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/projects')
@login_required
def projects():
    return render_template('projects.html')

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')

@app.route('/feedback')
@login_required
def feedback():
    return render_template('feedback.html')

@app.route('/timeline')
@login_required
def timeline():
    return render_template('timeline.html')

@app.route('/assignments')
@login_required
def assignments():
    return render_template('assignments.html')

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    report_type = request.form.get('report_type')
    date_range = request.form.get('date_range')
    format = request.form.get('format')
    
    # Get data based on report type and date range
    data = get_report_data(session['user_id'], report_type, date_range)
    
    # Render HTML template with data
    html = render_template('report_template.html', data=data)
    
    if format == 'pdf':
        # Generate PDF using pdfkit
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': 'UTF-8',
        }
        
        pdf = pdfkit.from_string(html, False, options=options)
        
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={report_type}_report.pdf'
        return response
    else:
        return html

def get_report_data(user_id, report_type, date_range):
    cur = mysql.connection.cursor()
    
    # Get user-specific data based on parameters
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    
    # Get report data based on type and date range
    query = """
        SELECT title, content, created_at 
        FROM journal_logs 
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 10
    """
    cur.execute(query, (user_id,))
    entries = cur.fetchall()
    
    cur.close()
    
    return {
        'user_name': user['name'],
        'report_type': report_type,
        'date_range': date_range,
        'entries': [
            {
                'date': entry['created_at'].strftime('%Y-%m-%d'),
                'title': entry['title'],
                'content': entry['content']
            } 
            for entry in entries
        ]
    }
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File uploaded successfully')
        return redirect(url_for('some_page'))
    
    # Example usage in a route
@app.route('/create_log', methods=['POST'])
def create_log():
    now = datetime.now()  # Get current timestamp
    # Use the timestamp when creating a log
    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO journal_logs (user_id, title, content, created_at) VALUES (%s, %s, %s, %s)",
        (session['user_id'], request.form['title'], request.form['content'], now)
    )
    mysql.connection.commit()
    cur.close()
    flash('Journal entry created!', 'success')
    return redirect(url_for('logs'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if email exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        
        if user:
            # In a real app, you would send a password reset email here
            flash('Password reset link has been sent to your email', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/upload_log/<int:log_id>', methods=['POST'])
@login_required
def upload_log(log_id):  # Now log_id is properly received as a parameter
    # Verify the log belongs to the current user
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM journal_logs WHERE id = %s", (log_id,))
    log = cur.fetchone()
    
    if not log or log['user_id'] != current_user.id:
        flash('Journal entry not found or access denied', 'danger')
        return redirect(url_for('logs'))
    
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('edit_log', log_id=log_id))  # Redirect back to edit page
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('edit_log', log_id=log_id))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Create unique filename to prevent collisions
        unique_filename = f"{log_id}_{current_user.id}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Save to database
        cur.execute(
            "INSERT INTO log_media (log_id, file_path, file_type) VALUES (%s, %s, %s)",
            (log_id, unique_filename, filename.rsplit('.', 1)[1].lower())
        )
        mysql.connection.commit()
        flash('File uploaded successfully', 'success')
    else:
        flash('Allowed file types are: png, jpg, jpeg, gif, pdf, doc, docx', 'danger')
    
    cur.close()
    return redirect(url_for('edit_log', log_id=log_id))

if __name__ == '__main__':
    app.run(debug=True)