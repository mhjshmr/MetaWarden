import os
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from PIL import Image
from PIL.ExifTags import TAGS
import json
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('evaluation_results.log'),
        logging.StreamHandler()
    ]
)

# Import functions from app.py
from app import get_image_metadata, calculate_privacy_score, is_readable_value

def load_ground_truth(csv_path):
    """Load and validate ground truth data from CSV"""
    try:
        df = pd.read_csv(csv_path)
        required_columns = ['image_name', 'GPSInfo', 'DateTimeOriginal', 'Make', 'Model', 'Software', 'ExifVersion', 'UserComment']
        
        # Validate columns
        if not all(col in df.columns for col in required_columns):
            missing_cols = [col for col in required_columns if col not in df.columns]
            raise ValueError(f"Missing required columns in ground truth file: {missing_cols}")
        
        # Convert binary columns to boolean
        for col in required_columns[1:]:  # Skip image_name column
            df[col] = df[col].astype(bool)
        
        return df
    except Exception as e:
        logging.error(f"Error loading ground truth file: {str(e)}")
        raise

def calculate_ground_truth_risk_level(row):
    """Calculate risk level based on ground truth metadata presence"""
    score = 10  # Start with perfect score
    
    # Apply same scoring logic as in app.py
    if row['GPSInfo']:
        score -= 3
    if row['Make'] or row['Model']:
        score -= 1
    if row['Software']:
        score -= 1
    if row['DateTimeOriginal']:
        score -= 1
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    # Get risk level using same logic as app.py
    if score >= 8:
        return "Safe"
    elif score >= 5:
        return "Moderate Risk"
    else:
        return "High Risk"

def evaluate_system(test_folder, ground_truth_df):
    """Evaluate system accuracy against ground truth"""
    results = {
        'predictions': [],
        'ground_truth': [],
        'image_names': [],
        'metadata_details': []
    }
    
    # Process each image
    for _, row in ground_truth_df.iterrows():
        image_name = row['image_name']
        image_path = os.path.join(test_folder, image_name)
        
        if not os.path.exists(image_path):
            logging.warning(f"Image not found: {image_path}")
            continue
        
        try:
            # Get metadata using system's function
            metadata, skipped_fields = get_image_metadata(image_path)
            
            # Calculate risk level using system's function
            score, risk_warnings, risk_level, risk_icon = calculate_privacy_score(metadata)
            
            # Get ground truth risk level
            ground_truth_risk = calculate_ground_truth_risk_level(row)
            
            # Store results
            results['predictions'].append(risk_level)
            results['ground_truth'].append(ground_truth_risk)
            results['image_names'].append(image_name)
            results['metadata_details'].append({
                'extracted_metadata': metadata,
                'skipped_fields': skipped_fields,
                'risk_warnings': risk_warnings,
                'score': score
            })
            
            logging.info(f"Processed {image_name}: System={risk_level}, Ground Truth={ground_truth_risk}")
            
        except Exception as e:
            logging.error(f"Error processing {image_name}: {str(e)}")
            continue
    
    return results

def calculate_metrics(results):
    """Calculate evaluation metrics"""
    y_true = results['ground_truth']
    y_pred = results['predictions']
    
    # Calculate overall accuracy
    accuracy = accuracy_score(y_true, y_pred)
    
    # Calculate precision, recall, F1 for each class
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, 
        labels=["Safe", "Moderate Risk", "High Risk"],
        average=None
    )
    
    # Create confusion matrix
    cm = confusion_matrix(
        y_true, y_pred,
        labels=["Safe", "Moderate Risk", "High Risk"]
    )
    
    # Create metrics summary
    metrics = {
        'accuracy': accuracy,
        'per_class_metrics': {
            label: {
                'precision': prec,
                'recall': rec,
                'f1': f1_score,
                'support': supp
            }
            for label, prec, rec, f1_score, supp in zip(
                ["Safe", "Moderate Risk", "High Risk"],
                precision, recall, f1, support
            )
        },
        'confusion_matrix': cm.tolist()
    }
    
    return metrics

def plot_confusion_matrix(cm, labels):
    """Plot and save confusion matrix"""
    plt.figure(figsize=(10, 8))
    sns.heatmap(
        cm, 
        annot=True, 
        fmt='d', 
        cmap='Blues',
        xticklabels=labels,
        yticklabels=labels
    )
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    plt.close()

def save_evaluation_report(metrics, results, output_file='evaluation_report.json'):
    """Save detailed evaluation report"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'metrics': metrics,
        'detailed_results': {
            name: {
                'predicted': pred,
                'ground_truth': true,
                'metadata_details': details
            }
            for name, pred, true, details in zip(
                results['image_names'],
                results['predictions'],
                results['ground_truth'],
                results['metadata_details']
            )
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logging.info(f"Evaluation report saved to {output_file}")

def main():
    # Configuration
    test_folder = r"C:\Users\LENOVO\Downloads\Test Sample"
    ground_truth_file = "ground_truth.csv"
    
    try:
        # Load ground truth data
        logging.info("Loading ground truth data...")
        ground_truth_df = load_ground_truth(ground_truth_file)
        
        # Evaluate system
        logging.info("Evaluating system...")
        results = evaluate_system(test_folder, ground_truth_df)
        
        # Calculate metrics
        logging.info("Calculating metrics...")
        metrics = calculate_metrics(results)
        
        # Plot confusion matrix
        logging.info("Generating confusion matrix plot...")
        plot_confusion_matrix(
            np.array(metrics['confusion_matrix']),
            ["Safe", "Moderate Risk", "High Risk"]
        )
        
        # Save evaluation report
        logging.info("Saving evaluation report...")
        save_evaluation_report(metrics, results)
        
        # Print summary
        logging.info("\nEvaluation Summary:")
        logging.info(f"Overall Accuracy: {metrics['accuracy']:.2%}")
        logging.info("\nPer-class Metrics:")
        for label, class_metrics in metrics['per_class_metrics'].items():
            logging.info(f"\n{label}:")
            logging.info(f"  Precision: {class_metrics['precision']:.2%}")
            logging.info(f"  Recall: {class_metrics['recall']:.2%}")
            logging.info(f"  F1-Score: {class_metrics['f1']:.2%}")
            logging.info(f"  Support: {class_metrics['support']}")
        
    except Exception as e:
        logging.error(f"Evaluation failed: {str(e)}")
        raise

if __name__ == "__main__":
    main() 