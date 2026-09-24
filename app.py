from flask import Flask, request, jsonify, render_template
import joblib
import pefile
import math
import os
import uuid
import tempfile
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ── Security Settings ─────────────────────────────────────────
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll'}

# ── Load Models ───────────────────────────────────────────────
rf_model = joblib.load('rf_model.pkl')
xgb_model = joblib.load('xgb_model.pkl')
le = joblib.load('label_encoder.pkl')

FEATURE_COLUMNS = [
    'machine_type', 'num_sections', 'timestamp', 'characteristics',
    'imagebase', 'entrypoint', 'dll_characteristics', 'file_size',
    'mean_section_entropy', 'max_section_entropy', 'min_section_entropy',
    'mean_section_size', 'num_imported_dlls', 'num_imports',
    'imports_cryptsp', 'imports_advapi32', 'imports_kernel32',
    'imports_wininet', 'imports_ws2_32', 'imports_vssapi',
    'num_exports', 'file_entropy'
]

# ── Helper Functions ──────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_features_from_file(filepath):
    features = {}
    try:
        pe = pefile.PE(filepath)

        features['machine_type'] = pe.FILE_HEADER.Machine
        features['num_sections'] = pe.FILE_HEADER.NumberOfSections
        features['timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['characteristics'] = pe.FILE_HEADER.Characteristics
        features['imagebase'] = pe.OPTIONAL_HEADER.ImageBase
        features['entrypoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['dll_characteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['file_size'] = os.path.getsize(filepath)

        section_entropies = []
        section_sizes = []
        for section in pe.sections:
            data = section.get_data()
            section_entropies.append(calculate_entropy(data))
            section_sizes.append(section.SizeOfRawData)

        features['mean_section_entropy'] = sum(section_entropies) / len(section_entropies) if section_entropies else 0
        features['max_section_entropy'] = max(section_entropies) if section_entropies else 0
        features['min_section_entropy'] = min(section_entropies) if section_entropies else 0
        features['mean_section_size'] = sum(section_sizes) / len(section_sizes) if section_sizes else 0

        imported_dlls = []
        num_imports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_dlls.append(entry.dll.decode(errors='ignore').lower())
                num_imports += len(entry.imports)

        features['num_imported_dlls'] = len(imported_dlls)
        features['num_imports'] = num_imports
        features['imports_cryptsp'] = int('cryptsp.dll' in imported_dlls)
        features['imports_advapi32'] = int('advapi32.dll' in imported_dlls)
        features['imports_kernel32'] = int('kernel32.dll' in imported_dlls)
        features['imports_wininet'] = int('wininet.dll' in imported_dlls)
        features['imports_ws2_32'] = int('ws2_32.dll' in imported_dlls)
        features['imports_vssapi'] = int('vssapi.dll' in imported_dlls)

        features['num_exports'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features['num_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        with open(filepath, 'rb') as f:
            raw = f.read()
        features['file_entropy'] = calculate_entropy(raw)

        return features, None

    except Exception as e:
        return None, str(e)

def predict(features):
    import pandas as pd
    X = pd.DataFrame([features])[FEATURE_COLUMNS]

    rf_proba = rf_model.predict_proba(X)[0]
    xgb_proba = xgb_model.predict_proba(X)[0]

    # Average both models
    avg_proba = (rf_proba + xgb_proba) / 2
    predicted_idx = avg_proba.argmax()
    predicted_family = le.classes_[predicted_idx]
    confidence = round(float(avg_proba[predicted_idx]) * 100, 2)

    # All family probabilities
    family_scores = {
        le.classes_[i]: round(float(avg_proba[i]) * 100, 2)
        for i in range(len(le.classes_))
    }

    return predicted_family, confidence, family_scores

# ── Routes ────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html', features=FEATURE_COLUMNS)

@app.route('/predict/file', methods=['POST'])
def predict_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Only .exe and .dll files are allowed'}), 400

    # Save to temp location with random name for security
    filename = str(uuid.uuid4()) + '.exe'
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(filepath)
        features, error = extract_features_from_file(filepath)

        if error:
            return jsonify({'error': f'Could not parse file: {error}'}), 400

        predicted_family, confidence, family_scores = predict(features)

        return jsonify({
            'success': True,
            'predicted_family': predicted_family,
            'confidence': confidence,
            'family_scores': family_scores,
            'mode': 'file'
        })

    finally:
        # Always delete the uploaded file after analysis
        if os.path.exists(filepath):
            os.remove(filepath)

@app.route('/predict/manual', methods=['POST'])
def predict_manual():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate all required features are present
        missing = [f for f in FEATURE_COLUMNS if f not in data]
        if missing:
            return jsonify({'error': f'Missing features: {missing}'}), 400

        features = {col: float(data[col]) for col in FEATURE_COLUMNS}
        predicted_family, confidence, family_scores = predict(features)

        return jsonify({
            'success': True,
            'predicted_family': predicted_family,
            'confidence': confidence,
            'family_scores': family_scores,
            'mode': 'manual'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'models_loaded': True})

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=False, host='127.0.0.1', port=5000)