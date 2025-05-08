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
from io import StringIO

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
                    try:
                        # Try to decode as UTF-8 first
                        data = data.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            # Try to decode as ASCII
                            data = data.decode('ascii')
                        except UnicodeDecodeError:
                            # If both fail, store as hex string
                            data = f"[Binary Data: {data.hex()}]"
                elif isinstance(data, (list, tuple, dict)):
                    # Convert complex data structures to string representation
                    data = str(data)
                metadata[str(tag)] = str(data)
        
        # Get basic image info
        metadata['Format'] = str(image.format)
        metadata['Mode'] = str(image.mode)
        metadata['Size'] = str(image.size)
        
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

def calculate_privacy_score(metadata):
    score = 10  # Start with perfect score
    risk_warnings = []
    
    # Check for GPS data
    if any('GPS' in key for key in metadata.keys()):
        score -= 3
        risk_warnings.append("GPS coordinates found in image")
    
    # Check for device information
    if any('Make' in key or 'Model' in key for key in metadata.keys()):
        score -= 1
        risk_warnings.append("Device information found")
    
    # Check for software information
    if any('Software' in key or 'Processing' in key for key in metadata.keys()):
        score -= 1
        risk_warnings.append("Software information found")
    
    # Check for date/time information
    if any('DateTime' in key for key in metadata.keys()):
        score -= 1
        risk_warnings.append("Date/Time information found")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    return score, risk_warnings

def generate_metadata_report(image, is_cleaned):
    # Create a StringIO buffer
    output = StringIO()
    
    # Write header
    output.write("Image Privacy Analysis Report\n")
    output.write("===========================\n\n")
    
    # Basic Information
    output.write("Basic Information\n")
    output.write("-----------------\n")
    output.write(f"Image Name: {image.original_filename}\n")
    output.write(f"Analysis Date: {image.upload_date.strftime('%Y-%m-%d %H:%M:%S')}\n")
    output.write(f"User: {image.user.username}\n")
    output.write(f"Metadata Cleaned: {'Yes' if is_cleaned else 'No'}\n\n")
    
    # Privacy Score
    privacy_score, risk_warnings = calculate_privacy_score(image.image_metadata)
    output.write("Privacy Assessment\n")
    output.write("-----------------\n")
    output.write(f"Privacy Score: {privacy_score}/10\n")
    
    if risk_warnings:
        output.write("\nRisk Warnings:\n")
        for warning in risk_warnings:
            output.write(f"- {warning}\n")
    else:
        output.write("\nNo significant privacy risks detected.\n")
    
    # Metadata Details
    output.write("\nMetadata Details\n")
    output.write("---------------\n")
    if isinstance(image.image_metadata, dict):
        for key, value in image.image_metadata.items():
            # Ensure both key and value are strings and properly encoded
            key_str = str(key).encode('ascii', 'ignore').decode('ascii')
            value_str = str(value).encode('ascii', 'ignore').decode('ascii')
            output.write(f"{key_str}: {value_str}\n")
    else:
        output.write("No metadata available\n")
    
    return output.getvalue()

@app.route('/download_metadata/<int:image_id>')
@login_required
def download_metadata(image_id):
    image = AnalyzedImage.query.get_or_404(image_id)
    if image.user_id != current_user.id:
        abort(403)
    
    # Check if the image has been cleaned
    is_cleaned = image.filename.startswith('cleaned_')
    
    # Generate the report
    report_content = generate_metadata_report(image, is_cleaned)
    
    # Create a response with the text content
    response = current_app.response_class(
        report_content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename=privacy_report_{image.original_filename.rsplit(".", 1)[0]}.txt'
        }
    )
    
    return response

def format_metadata_value(value):
    """Helper function to format metadata values in a clean way"""
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return value.decode('ascii')
            except UnicodeDecodeError:
                return f"[Binary Data: {value.hex()}]"
    elif isinstance(value, (list, tuple)):
        return ', '.join(str(item) for item in value)
    elif isinstance(value, dict):
        return ', '.join(f"{k}: {v}" for k, v in value.items())
    else:
        return str(value)

def generate_raw_metadata_report(image):
    """Generate a clean, formatted metadata report"""
    # Create a StringIO buffer
    output = StringIO()
    
    # Write header
    output.write("Image Metadata Report\n")
    output.write("===================\n\n")
    
    # Write metadata
    if isinstance(image.image_metadata, dict):
        for key, value in sorted(image.image_metadata.items()):
            # Ensure both key and value are strings and properly encoded
            key_str = str(key).encode('ascii', 'ignore').decode('ascii')
            value_str = str(value).encode('ascii', 'ignore').decode('ascii')
            output.write(f"{key_str}: {value_str}\n")
    else:
        output.write("No metadata available\n")
    
    return output.getvalue()

@app.route('/download_raw_metadata/<int:image_id>')
@login_required
def download_raw_metadata(image_id):
    image = AnalyzedImage.query.get_or_404(image_id)
    if image.user_id != current_user.id:
        abort(403)
    
    # Generate the raw metadata report
    report_content = generate_raw_metadata_report(image)
    
    # Create a response with the text content
    response = current_app.response_class(
        report_content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename=metadata_{image.original_filename.rsplit(".", 1)[0]}.txt'
        }
    )
    
    return response

@app.route('/download_privacy_report/<int:image_id>')
@login_required
def download_privacy_report(image_id):
    image = AnalyzedImage.query.get_or_404(image_id)
    if image.user_id != current_user.id:
        abort(403)
    
    # Check if the image has been cleaned
    is_cleaned = image.filename.startswith('cleaned_')
    
    # Generate the comprehensive privacy report
    report_content = generate_metadata_report(image, is_cleaned)
    
    # Create a response with the text content
    response = current_app.response_class(
        report_content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename=privacy_report_{image.original_filename.rsplit(".", 1)[0]}.txt'
        }
    )
    
    return response

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5500) 