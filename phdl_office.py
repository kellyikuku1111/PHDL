import os
from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, FileField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime

# --- Configuration ---
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'static', 'user_images')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DB_NAME = os.path.join(APP_ROOT, 'office_system.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = '12345678'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            department TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            image_path TEXT,
            dob TEXT,
            user_type TEXT
        )
    ''')
    # Create default admin if not exists
    c.execute("SELECT * FROM users WHERE is_admin=1")
    if not c.fetchone():
        c.execute('''
            INSERT INTO users (name, phone, department, username, password, is_admin)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', ("Admin", "0000000000", "Administration", "admin", generate_password_hash("admin123")))
    conn.commit()
    conn.close()

init_db()

# --- Forms ---
class RegistrationForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    phone = StringField('Phone Number', validators=[DataRequired(), Regexp(r'^\d{10,15}$', message="Enter a valid phone number")])
    department = SelectField('Department', choices=[
        ("HR", "HR"), ("ICT", "ICT"), ("Finance", "Finance"), ("Marketing", "Marketing"),
        ("APR", "APR"), ("Admin Office", "Admin Office"), ("Survey", "Survey"),
        ("Engineering", "Engineering"), ("Legal", "Legal"), ("Audit", "Audit"),
        ("Record", "Record"), ("Architecture", "Architecture"), ("Studio 400", "Studio 400")
    ])
    user_type = SelectField('User Type', choices=[
        ("Staff", "Staff"), ("Personnel", "Personnel"), ("Corper", "Corper"), ("IT Student", "IT Student")
    ])
    dob = StringField('Date of Birth (YYYY-MM-DD)', validators=[DataRequired(), Regexp(r'^\d{4}-\d{2}-\d{2}$', message="Format: YYYY-MM-DD")])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    image = FileField('Upload Picture')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --- Helper Functions ---
def get_user_by_username(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    return user

def save_user(form, filename):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        INSERT INTO users (name, phone, department, username, password, image_path, dob, user_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        form.name.data, form.phone.data, form.department.data, form.username.data,
        generate_password_hash(form.password.data), filename, form.dob.data, form.user_type.data
    ))
    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}

def find_users_by_name(name):
    """Return a list of users whose name contains the given string (case-insensitive)."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE name LIKE ?", ('%' + name + '%',))
    users = c.fetchall()
    conn.close()
    return users

def get_department_counts():
    """Return a dictionary: {department: user_count} for all departments."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT department, COUNT(*) FROM users GROUP BY department")
    dept_counts = dict(c.fetchall())
    conn.close()
    return dept_counts

def get_total_user_count():
    """Return the total number of users."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    total = c.fetchone()[0]
    conn.close()
    return total

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user and user[6]:  # is_admin
            return redirect(url_for('admin_dashboard'))
        elif user:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        print("Form validated")  # Add this
        if get_user_by_username(form.username.data):
            flash('Username already exists.', 'danger')
            return render_template('register.html', form=form)
        filename = None
        if form.image.data and allowed_file(form.image.data.filename):
            filename = secure_filename(form.username.data + os.path.splitext(form.image.data.filename)[1])
            form.image.data.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            filename = 'user_images/' + filename
        else:
            filename = None
        save_user(form, filename)
        print("User saved")  # Add this
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    else:
        print("Form errors:", form.errors)  # Add this
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("Login form validated")  # Add this
        user = get_user_by_username(form.username.data)
        print("User found:", user)  # Add this
        if user and check_password_hash(user[5], form.password.data):
            session['user_id'] = user[0]
            if user[6]:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    else:
        print("Login form errors:", form.errors)  # Add this
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user_by_id(session['user_id'])
    if not user or not user[6]:
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, name, phone, department, username, dob, user_type, image_path FROM users WHERE is_admin=0")
    users = c.fetchall()
    conn.close()
    dept_counts = get_department_counts()
    total_users = get_total_user_count()
    return render_template('admin_dashboard.html', users=users, admin=user, dept_counts=dept_counts, total_users=total_users)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user_by_id(session['user_id'])
    if not user or not user[6]:
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT image_path FROM users WHERE id=?", (user_id,))
    img = c.fetchone()
    if img and img[0]:
        try:
            os.remove(os.path.join(app.root_path, 'static', img[0]))
        except Exception:
            pass
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/user')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    # Count users in the same department
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE department = ?", (user[3],))
    dept_count = c.fetchone()[0]
    conn.close()
    dept_counts = get_department_counts()  # <-- Add this line
    return render_template('user_dashboard.html', user=user, dept_count=dept_count, dept_counts=dept_counts)  # <-- Pass dept_counts

@app.route('/admin/search', methods=['GET', 'POST'])
def admin_search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user_by_id(session['user_id'])
    if not user or not user[6]:
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))
    search_results = []
    query = ""
    if request.method == 'POST':
        query = request.form.get('name', '')
        search_results = find_users_by_name(query)
    dept_counts = get_department_counts()
    total_users = get_total_user_count()
    return render_template('admin_search.html', admin=user, results=search_results, query=query, dept_counts=dept_counts, total_users=total_users)

@app.route('/time')
def show_time():
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    return render_template('show_time.html', current_time=current_time)

@app.context_processor
def inject_now():
    return {'current_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

# --- Templates ---
# Place the following HTML files in a 'templates' folder in the same directory as this script:
#
# login.html, register.html, admin_dashboard.html, user_dashboard.html
#
# Each template should extend a base.html with Bootstrap included.
# If you want, I can provide the HTML templates as well.

if __name__ == '__main__':
    app.run(debug=True)