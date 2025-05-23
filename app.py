import os
from flask import Flask, request, render_template, send_file, current_app, url_for, flash, redirect, abort, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from PIL import Image
from PIL.ExifTags import TAGS
from models import db, User, AnalyzedImage
import json
from datetime import datetime
from werkzeug.security import generate_password_hash
from io import StringIO
import openai

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

app.config['OPENAI_API_KEY'] = os.getenv("OPENAI_API_KEY")
openai.api_key = app.config['OPENAI_API_KEY']

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_readable_value(value):
    """Check if a value is readable and can be safely converted to string"""
    if isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, (list, tuple)):
        return all(is_readable_value(item) for item in value)
    if isinstance(value, dict):
        return all(is_readable_value(k) and is_readable_value(v) for k, v in value.items())
    return False

def get_image_metadata(image_path):
    try:
        image = Image.open(image_path)
        exif = image._getexif()
        metadata = {}
        skipped_fields = []
        
        if exif is not None:
            # Create a mutable copy to modify
            exif_dict = dict(exif)
            
            # First, handle GPS data specifically
            if 34853 in exif_dict:  # GPSInfo tag
                try:
                    gps_info = exif_dict[34853]
                    gps_data = {}
                    
                    # GPS Latitude
                    if 2 in gps_info and 1 in gps_info:
                        lat_ref = gps_info[1]
                        lat = gps_info[2]
                        lat_deg = lat[0] + lat[1]/60.0 + lat[2]/3600.0
                        if lat_ref == 'S':
                            lat_deg = -lat_deg
                        gps_data['GPS Latitude'] = f"{lat_deg:.6f}°"
                    
                    # GPS Longitude
                    if 4 in gps_info and 3 in gps_info:
                        lon_ref = gps_info[3]
                        lon = gps_info[4]
                        lon_deg = lon[0] + lon[1]/60.0 + lon[2]/3600.0
                        if lon_ref == 'W':
                            lon_deg = -lon_deg
                        gps_data['GPS Longitude'] = f"{lon_deg:.6f}°"
                    
                    # GPS Altitude
                    if 6 in gps_info:
                        alt = gps_info[6]
                        alt_ref = gps_info[5] if 5 in gps_info else 0
                        altitude = float(alt[0]) / float(alt[1])
                        if alt_ref == 1:  # Below sea level
                            altitude = -altitude
                        gps_data['GPS Altitude'] = f"{altitude:.2f} meters"
                    
                    # GPS Timestamp
                    if 7 in gps_info:
                        time = gps_info[7]
                        gps_data['GPS Timestamp'] = f"{time[0]}:{time[1]}:{time[2]}"
                    
                    # Add all GPS data to metadata
                    metadata.update(gps_data)
                    
                    # Remove the GPSInfo tag from the dictionary so it's not processed again
                    del exif_dict[34853]
                    
                except Exception as e:
                    skipped_fields.append(f"GPS data: Error processing GPS information - {str(e)}")
            
            # Process other EXIF tags from the modified dictionary
            for tag_id in exif_dict:
                tag = TAGS.get(tag_id, tag_id)
                data = exif_dict.get(tag_id)
                
                # Skip binary data and unreadable fields
                if isinstance(data, bytes):
                    # Only try to decode if it's a text field
                    if tag in ['UserComment', 'ImageDescription', 'Copyright', 'Artist', 'Software']:
                        try:
                            # Try multiple encodings for known text fields
                            for encoding in ['utf-8', 'ascii', 'latin1']:
                                try:
                                    decoded = data.decode(encoding)
                                    if decoded.strip():  # Only keep non-empty strings
                                        metadata[str(tag)] = decoded
                                    break
                                except UnicodeDecodeError:
                                    continue
                        except Exception as e:
                            skipped_fields.append(f"{tag}: Binary data that couldn't be decoded")
                    else:
                        skipped_fields.append(f"{tag}: Binary data (skipped)")
                    continue
                
                # Handle complex data structures
                if isinstance(data, (list, tuple)):
                    try:
                        # Only keep readable items
                        readable_items = [str(item) for item in data if is_readable_value(item)]
                        if readable_items:
                            metadata[str(tag)] = ', '.join(readable_items)
                        else:
                            skipped_fields.append(f"{tag}: List/tuple with no readable items")
                    except Exception as e:
                        skipped_fields.append(f"{tag}: Error formatting list/tuple")
                    continue
                
                if isinstance(data, dict):
                    try:
                        # Only keep readable key-value pairs
                        readable_pairs = [f"{k}: {v}" for k, v in data.items() 
                                        if is_readable_value(k) and is_readable_value(v)]
                        if readable_pairs:
                            metadata[str(tag)] = ', '.join(readable_pairs)
                        else:
                            skipped_fields.append(f"{tag}: Dictionary with no readable items")
                    except Exception as e:
                        skipped_fields.append(f"{tag}: Error formatting dictionary")
                    continue
                
                # Handle basic types
                if is_readable_value(data):
                    try:
                        # Convert to string and ensure it's valid UTF-8
                        str_value = str(data)
                        # Test if it can be properly encoded/decoded as UTF-8
                        str_value.encode('utf-8').decode('utf-8')
                        metadata[str(tag)] = str_value
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        skipped_fields.append(f"{tag}: Value contains invalid UTF-8 characters")
                else:
                    skipped_fields.append(f"{tag}: Unreadable data type")
        
        # Get basic image info (always readable)
        metadata['Format'] = str(image.format)
        metadata['Mode'] = str(image.mode)
        metadata['Size'] = str(image.size)
        
        # Log skipped fields
        if skipped_fields:
            current_app.logger.info(f"Skipped metadata fields in {image_path}:")
            for field in skipped_fields:
                current_app.logger.info(f"  - {field}")
        
        return metadata, skipped_fields
    except Exception as e:
        current_app.logger.error(f"Error extracting metadata from {image_path}: {str(e)}")
        return {'Error': str(e)}, [f"Error extracting metadata: {str(e)}"]

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
        
        # Get metadata with skipped fields tracking
        image_metadata, skipped_fields = get_image_metadata(filepath)
        
        # Log skipped fields
        if skipped_fields:
            for field in skipped_fields:
                current_app.logger.info(f"Skipped metadata field in {filename}: {field}")
            flash(f'Image analyzed with {len(skipped_fields)} metadata fields skipped (unreadable or binary data)', 'info')
        else:
            flash('Image analyzed successfully!', 'success')
        
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
    
    # Get risk level and icon
    risk_level, risk_icon = get_risk_level(score)
    
    return score, risk_warnings, risk_level, risk_icon

def get_risk_level(score):

    if score >= 8:
        return "Safe", "✅"
    elif score >= 5:
        return "Moderate Risk", "⚠️"
    else:
        return "High Risk", "🚨"

def format_metadata_value(value):
    """Helper function to format metadata values in a clean way"""
    if isinstance(value, bytes):
        try:
            # Try multiple encodings in order of preference
            for encoding in ['utf-8', 'ascii', 'latin1']:
                try:
                    return value.decode(encoding)
                except UnicodeDecodeError:
                    continue
            # If all encodings fail, return hex representation
            return f"[Binary Data: {value.hex()}]"
        except Exception as e:
            return f"[Error decoding binary data: {str(e)}]"
    elif isinstance(value, (list, tuple)):
        try:
            return ', '.join(str(item) for item in value)
        except Exception as e:
            return f"[Error formatting list/tuple: {str(e)}]"
    elif isinstance(value, dict):
        try:
            return ', '.join(f"{k}: {v}" for k, v in value.items())
        except Exception as e:
            return f"[Error formatting dict: {str(e)}]"
    else:
        try:
            # Ensure the value is properly encoded as UTF-8
            return str(value).encode('utf-8', errors='replace').decode('utf-8')
        except Exception as e:
            return f"[Error formatting value: {str(e)}]"

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
    privacy_score, risk_warnings, risk_level, risk_icon = calculate_privacy_score(image.image_metadata)
    output.write("Privacy Assessment\n")
    output.write("-----------------\n")
    output.write(f"Privacy Score: {privacy_score}/10\n")
    output.write(f"Risk Level: {risk_level}\n")
    output.write(f"Risk Icon: {risk_icon}\n")
    
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
        # Sort metadata by key for consistent output
        for key, value in sorted(image.image_metadata.items()):
            # Skip any remaining non-string values
            if not isinstance(value, str):
                continue
            try:
                # Ensure the value is valid UTF-8
                value.encode('utf-8').decode('utf-8')
                output.write(f"{key}: {value}\n")
            except UnicodeError:
                # Skip values that can't be properly encoded as UTF-8
                continue
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
            # Use the same robust formatting function as other reports
            key_str = format_metadata_value(key)
            value_str = format_metadata_value(value)
            
            # Ensure the output is clean UTF-8
            try:
                output.write(f"{key_str}: {value_str}\n")
            except UnicodeEncodeError:
                # If we still get encoding errors, use replacement character
                output.write(f"{key_str.encode('utf-8', errors='replace').decode('utf-8')}: "
                           f"{value_str.encode('utf-8', errors='replace').decode('utf-8')}\n")
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

@app.route('/delete_image/<int:image_id>', methods=['POST'])
@login_required
def delete_image(image_id):
    image = AnalyzedImage.query.get_or_404(image_id)
    if image.user_id != current_user.id:
        abort(403)
    
    try:
        # Delete the image file from uploads folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete the database record
        db.session.delete(image)
        db.session.commit()
        flash('Image deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting image', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/delete_all_images', methods=['POST'])
@login_required
def delete_all_images():
    try:
        # Get all images for the current user
        images = AnalyzedImage.query.filter_by(user_id=current_user.id).all()
        
        # Delete image files from uploads folder
        for image in images:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete all database records for the user
        AnalyzedImage.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        flash('All images deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting images', 'error')
    
    return redirect(url_for('dashboard'))

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5500) 