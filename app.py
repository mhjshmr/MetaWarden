import os
from flask import Flask, request, render_template, send_file, current_app, url_for, flash, redirect, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from PIL import Image
from PIL.ExifTags import TAGS
from models import db, User, AnalyzedImage
import json
from datetime import datetime
from werkzeug.security import generate_password_hash

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# Configure the app
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_image_metadata(image_path):
    try:
        image = Image.open(image_path)
        exif = image._getexif()
        metadata = {}
        
        if exif is not None:
            for tag_id in exif:
                tag = TAGS.get(tag_id, tag_id)
                data = exif.get(tag_id)
                if isinstance(data, bytes):
                    data = data.decode(errors='replace')
                metadata[tag] = str(data)
        
        # Get basic image info
        metadata['Format'] = image.format
        metadata['Mode'] = image.mode
        metadata['Size'] = image.size
        
        return metadata
    except Exception as e:
        return {'Error': str(e)}

def remove_metadata(image_path):
    try:
        # Open the image
        image = Image.open(image_path)
        
        # Create a new image without EXIF data
        data = list(image.getdata())
        new_image = Image.new(image.mode, image.size)
        new_image.putdata(data)
        
        # Save the new image
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'cleaned_' + os.path.basename(image_path))
        new_image.save(output_path, quality=95)
        
        return output_path
    except Exception as e:
        return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate required fields
        if not username or not email or not password:
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    images = AnalyzedImage.query.filter_by(user_id=current_user.id).order_by(AnalyzedImage.upload_date.desc()).all()
    return render_template('dashboard.html', images=images)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Get metadata
        image_metadata = get_image_metadata(filepath)
        
        # Remove metadata if requested
        cleaned_file = None
        if request.form.get('remove_metadata') == 'yes':
            cleaned_file = remove_metadata(filepath)
            if cleaned_file:
                filename = 'cleaned_' + filename
        
        # Save to database
        analyzed_image = AnalyzedImage(
            filename=filename,
            original_filename=file.filename,
            image_metadata=image_metadata,
            user_id=current_user.id
        )
        db.session.add(analyzed_image)
        db.session.commit()
        
        flash('Image analyzed successfully!', 'success')
        return redirect(url_for('view_image', image_id=analyzed_image.id))
    
    flash('Invalid file type', 'error')
    return redirect(url_for('dashboard'))

@app.route('/image/<int:image_id>')
@login_required
def view_image(image_id):
    image = AnalyzedImage.query.get_or_404(image_id)
    if image.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if the image has been cleaned (metadata removed)
    is_cleaned = image.filename.startswith('cleaned_')
    
    return render_template('result.html', 
                         metadata=image.image_metadata,
                         original_file=image.original_filename,
                         cleaned_file=image.filename,
                         image_id=image_id,
                         is_cleaned=is_cleaned)

@app.route('/download_original/<int:image_id>')
@login_required
def download_original(image_id):
    image = AnalyzedImage.query.get_or_404(image_id)
    if image.user_id != current_user.id:
        abort(403)
    
    # Get the original image path
    original_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
    
    # Check if the original file exists
    if not os.path.exists(original_path):
        flash('Original image file not found', 'error')
        return redirect(url_for('view_image', image_id=image_id))
    
    # Send the original file
    return send_file(
        original_path,
        as_attachment=True,
        download_name=image.original_filename
    )

@app.route('/download_image/<int:image_id>')
@login_required
def download_image(image_id):
    image = AnalyzedImage.query.get_or_404(image_id)
    if image.user_id != current_user.id:
        abort(403)
    
    # Get the cleaned image path
    cleaned_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
    
    # Check if the cleaned file exists
    if not os.path.exists(cleaned_path):
        flash('Cleaned image file not found', 'error')
        return redirect(url_for('view_image', image_id=image_id))
    
    # Send the cleaned file
    return send_file(
        cleaned_path,
        as_attachment=True,
        download_name=f"cleaned_{image.original_filename}"
    )

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5500) 