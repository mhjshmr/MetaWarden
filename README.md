# Image Metadata Detector and Remover

A Flask web application that allows users to upload images, detect their metadata, and optionally remove the metadata from the images.

## Features

- Upload images (supports PNG, JPG, JPEG, and GIF formats)
- Detect and display image metadata including EXIF data
- Option to remove metadata from images
- Download both original and cleaned images
- Modern and user-friendly interface

## Setup

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your web browser and navigate to `http://localhost:5000`

## Usage

1. Click on the upload area or drag and drop an image file
2. Check the "Remove metadata from image" box if you want to remove the metadata
3. Click "Analyze Image" to process the image
4. View the detected metadata in the results page
5. Download either the original or cleaned image (if metadata removal was selected)

## Technical Details

- Built with Flask web framework
- Uses Pillow for image processing
- Supports common image formats (PNG, JPG, JPEG, GIF)
- Maximum file size: 16MB
- Stores uploaded files in the `uploads` directory

## Security Notes

- All uploaded files are sanitized using `secure_filename`
- File types are validated before processing
- Maximum file size is enforced
- Temporary files are stored in a dedicated uploads directory 