from flask import Flask, request, jsonify, render_template
import os
import json
import tempfile
import logging
import time  # Dodany brakujący import
from werkzeug.utils import secure_filename
from pdfid import PDFiD, PDFiD2JSON
import uuid
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_talisman import Talisman
import fitz  # PyMuPDF
import re
import base64
from io import BytesIO
from PIL import Image
from flask_limiter import Limiter
from virustotal_api import get_virustotal_api


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

Talisman(app, 
    force_https=False,
    strict_transport_security=False,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:", # Dodajemy obsługę data URI dla obrazów
    },
)


if os.name == 'nt':  # Windows
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'temp_uploads')
    log_file = os.path.join(os.getcwd(), 'logs', 'pdf_analyzer.log')
else:  # Linux/Mac
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'temp_uploads')
    log_file = os.path.join(os.getcwd(), 'logs', 'pdf_analyzer.log')

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.dirname(log_file), exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

ALLOWED_EXTENSIONS = {'pdf'}
DANGER_KEYWORDS = ['/JS', '/JavaScript', '/AA', '/OpenAction', '/Launch', '/EmbeddedFile']

TRANSLATIONS = {
    'No file provided': 'Nie przesłano pliku',
    'No file selected': 'Nie wybrano pliku',
    'Only PDF files are allowed': 'Dozwolone są tylko pliki PDF',
    'File processing failed': 'Przetwarzanie pliku nie powiodło się',
    'Analysis failed': 'Analiza nie powiodła się',
    'PDF is encrypted': 'PDF jest zaszyfrowany',
    'High number of objects': 'Duża liczba obiektów'
}

def translate_message(message):
    """Translate message to Polish"""
    return TRANSLATIONS.get(message, message)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_delete_file(file_path):
    """Securely delete file by overwriting with zeros before deletion"""
    try:
        if not os.path.exists(file_path):
            return True
            
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Overwrite file with zeros multiple times for security
        with open(file_path, 'r+b') as f:
            # First pass: zeros
            f.seek(0)
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
            
            # Second pass: random data
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
            
            # Third pass: zeros again
            f.seek(0)
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
        
        # Finally delete the file
        os.remove(file_path)
        logging.info(f"File securely deleted: {file_path}")
        return True
        
    except Exception as e:
        logging.error(f"Error securely deleting file {file_path}: {str(e)}")
        # Fallback to regular deletion
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.warning(f"File deleted with fallback method: {file_path}")
        except:
            logging.error(f"Failed to delete file even with fallback: {file_path}")
        return False

def analyze_pdf_safety_metadata_only(file_path):
    """Szybka analiza metadanych bez otwierania treści PDF"""
    try:
        xmlDoc = PDFiD(file_path, allNames=False, extraData=True, disarm=False, force=False)
        json_result = PDFiD2JSON(xmlDoc, False)
        data = json.loads(json_result)[0]['pdfid']
        
        dangerous_elements = {
            'javascript': 0,
            'actions': 0,
            'launch': 0,
            'embedded': 0,
            'xfa': 0
        }
        
        # Sprawdź niebezpieczne elementy
        for keyword in data['keywords']['keyword']:
            name = keyword['name']
            count = keyword['count']
            
            if name in ['/JS', '/JavaScript'] and count > 0:
                dangerous_elements['javascript'] = count
            elif name in ['/AA', '/OpenAction'] and count > 0:
                dangerous_elements['actions'] = count
            elif name == '/Launch' and count > 0:
                dangerous_elements['launch'] = count
            elif name == '/EmbeddedFile' and count > 0:
                dangerous_elements['embedded'] = count
            elif name == '/XFA' and count > 0:
                dangerous_elements['xfa'] = count
        
        # Określ czy plik jest bezpieczny do dalszej analizy
        is_safe_to_open = all(count == 0 for count in dangerous_elements.values())
        
        return {
            'safe_to_open': is_safe_to_open,
            'dangerous_elements': dangerous_elements,
            'pdfid_data': data
        }
    except Exception as e:
        logging.error(f"Error in metadata analysis: {str(e)}")
        return {
            'safe_to_open': False,
            'dangerous_elements': {'error': 1},
            'pdfid_data': None
        }

def extract_links_from_pdf(file_path):
    """Extract links from PDF and analyze them for potential risks"""
    links = []
    seen_links = set()
    suspicious_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'rebrand.ly',
        'tiny.cc', 'tr.im', 'cutt.ly', 'shorturl.at', 'rb.gy', 'soo.gd', 'sprl.in'
    ]
    
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w%!./?=&+#]*)*'
    broken_url_pattern = r'(https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+)[-\w%!./?=&+#]*(?:\n|\r\n|\r)[-\w%!./?=&+#]*'
    
    doc = None
    try:
        # KRYTYCZNE: Sprawdź bezpieczeństwo przed otwarciem
        metadata_check = analyze_pdf_safety_metadata_only(file_path)
        if not metadata_check['safe_to_open']:
            logging.warning(f"Skipping link extraction due to dangerous elements: {metadata_check['dangerous_elements']}")
            return []  # Nie otwieraj niebezpiecznych plików
        
        doc = fitz.open(file_path)
        
        # 1. Najpierw zbieramy aktywne hiperłącza
        for page_num in range(len(doc)):
            page = doc[page_num]
            page_links = page.get_links()
            page_seen_links = set()  # Zbiór do śledzenia linków na danej stronie
            
            for link in page_links:
                if 'uri' in link:
                    url = link['uri']
                    
                    # Unikaj duplikatów linków na tej samej stronie
                    link_key = f"{url}_{page_num}"
                    if link_key in page_seen_links:
                        continue
                    
                    page_seen_links.add(link_key)
                    
                    # Sprawdź, czy ten link już widzieliśmy na wcześniejszych stronach
                    # Jeśli tak, aktualizujemy informację o stronie zamiast dodawać duplikat
                    existing_link_idx = next((i for i, l in enumerate(links) if l['url'] == url), None)
                    
                    is_suspicious = False
                    reason = []
                    
                    # Check for URL shorteners and other suspicious patterns
                    for domain in suspicious_domains:
                        if domain in url.lower():
                            is_suspicious = True
                            reason.append("skrócony URL")
                            break
                    
                    # Check for non-HTTPS
                    if url.startswith('http://'):
                        is_suspicious = True
                        reason.append("nieszyfrowane połączenie")
                    
                    # Check for unusual TLDs
                    unusual_tlds = ['.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf']
                    for tld in unusual_tlds:
                        if url.lower().endswith(tld):
                            is_suspicious = True
                            reason.append(f"nietypowa domena {tld}")
                            break
                    
                    # Check for IP addresses in URLs
                    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                        is_suspicious = True
                        reason.append("adres IP zamiast domeny")
                    
                    if existing_link_idx is not None:
                        # Jeśli link już istnieje, dodajemy informację o stronie
                        existing_link = links[existing_link_idx]
                        if page_num + 1 not in existing_link['pages']:
                            existing_link['pages'].append(page_num + 1)
                    else:
                        # Dodajemy nowy link
                        links.append({
                            'url': url,
                            'pages': [page_num + 1],  # Lista stron, na których występuje link
                            'page': page_num + 1,     # Zachowujemy kompatybilność ze starym formatem
                            'source': 'hyperlink',    # Oznaczamy źródło linku
                            'suspicious': is_suspicious,
                            'reason': ", ".join(reason) if reason else None
                        })
        
        # 2. Teraz szukamy URLi w tekście dokumentu
        for page_num in range(len(doc)):
            page = doc[page_num]
            text = page.get_text()
            
            # Znajdź wszystkie URLe w tekście
            urls = re.findall(url_pattern, text)
            
            # Szukaj też URLi przedzielonych znakiem nowej linii
            broken_url_matches = re.finditer(broken_url_pattern, text)
            for match in broken_url_matches:
                # Pobierz linię, która zawiera początek URLa
                line_start = text.rfind('\n', 0, match.start()) + 1
                if line_start == 0:  # Jeśli nie znaleziono znaku nowej linii przed URLem
                    line_start = 0
                
                # Pobierz linię, która zawiera koniec URLa
                line_end = text.find('\n', match.end())
                if line_end == -1:  # Jeśli nie znaleziono znaku nowej linii po URLu
                    line_end = len(text)
                
                # Złącz obie linie i usuń znak nowej linii
                context = text[line_start:line_end].replace('\n', '')
                
                # Spróbuj znaleźć pełny URL w kontekście
                potential_url = re.search(url_pattern, context)
                if potential_url:
                    urls.append(potential_url.group(0))
            
            # Przetwórz znalezione URLe
            for url in urls:
                # Sprawdź, czy już dodaliśmy ten URL
                if url in seen_links:
                    # Znajdź istniejący URL i dodaj informację o tej stronie
                    existing_link_idx = next((i for i, l in enumerate(links) if l['url'] == url), None)
                    if existing_link_idx is not None and page_num + 1 not in links[existing_link_idx]['pages']:
                        links[existing_link_idx]['pages'].append(page_num + 1)
                    continue
                
                seen_links.add(url)
                
                # Sprawdzanie czy URL jest podejrzany
                is_suspicious = False
                reason = []
                
                # Check for URL shorteners
                for domain in suspicious_domains:
                    if domain in url.lower():
                        is_suspicious = True
                        reason.append("skrócony URL")
                        break
                
                # Check for non-HTTPS
                if url.startswith('http://'):
                    is_suspicious = True
                    reason.append("nieszyfrowane połączenie")
                
                # Check for unusual TLDs
                unusual_tlds = ['.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf']
                for tld in unusual_tlds:
                    if url.lower().endswith(tld):
                        is_suspicious = True
                        reason.append(f"nietypowa domena {tld}")
                        break
                
                # Check for IP addresses in URLs
                if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                    is_suspicious = True
                    reason.append("adres IP zamiast domeny")
                
                # Sprawdź, czy link nie jest już na liście (jako aktywny hiperlink)
                existing_link_idx = next((i for i, l in enumerate(links) if l['url'] == url), None)
                if existing_link_idx is None:
                    # Dodaj nowy link z tekstu
                    links.append({
                        'url': url,
                        'pages': [page_num + 1],
                        'page': page_num + 1,
                        'source': 'text',  # Oznaczamy, że link został znaleziony w tekście
                        'suspicious': is_suspicious,
                        'reason': ", ".join(reason) if reason else None
                    })
                else:
                    # Aktualizuj istniejący link o informację o tej stronie
                    if page_num + 1 not in links[existing_link_idx]['pages']:
                        links[existing_link_idx]['pages'].append(page_num + 1)
        
        return links
    
    except Exception as e:
        logging.error(f"Error extracting links: {str(e)}")
        return []
    finally:
        # Upewnij się, że dokument zostanie zamknięty
        if doc:
            try:
                doc.close()
            except:
                pass

def analyze_pdf_safety(file_path):
    """Analyze PDF and return safety assessment"""
    try:
        # KROK 1: Szybka analiza metadanych
        metadata_check = analyze_pdf_safety_metadata_only(file_path)
        data = metadata_check['pdfid_data']
        
        if not data:
            raise Exception("Nie można odczytać metadanych PDF")
        
        # KROK 2: Podstawowa analiza ryzyka na podstawie metadanych
        risk_score = 0
        warnings = []
        dangerous_elements = metadata_check['dangerous_elements']
        
        content_binary = {
            'javascript': 0,
            'actions': 0,
            'launch': 0,
            'embedded': 0,
            'forms': 0,
            'encryption': 0,
            'large_objects': 0,
            'xfa': 0
        }
        
        # Analiza niebezpiecznych elementów
        if dangerous_elements.get('javascript', 0) > 0:
            count = dangerous_elements['javascript']
            risk_score += count * 15
            warnings.append(f"Zawiera {count} wystąpień JavaScript")
            content_binary['javascript'] = 1
            
        if dangerous_elements.get('actions', 0) > 0:
            count = dangerous_elements['actions']
            risk_score += count * 12
            warnings.append(f"Zawiera {count} automatycznych akcji")
            content_binary['actions'] = 1
            
        if dangerous_elements.get('launch', 0) > 0:
            count = dangerous_elements['launch']
            risk_score += count * 20
            warnings.append(f"Zawiera {count} akcji uruchamiania")
            content_binary['launch'] = 1
            
        if dangerous_elements.get('embedded', 0) > 0:
            count = dangerous_elements['embedded']
            risk_score += count * 8
            warnings.append(f"Zawiera {count} osadzonych plików")
            content_binary['embedded'] = 1
            
        if dangerous_elements.get('xfa', 0) > 0:
            count = dangerous_elements['xfa']
            risk_score += count * 5
            warnings.append(f"Zawiera {count} formularzy XFA")
            content_binary['xfa'] = 1
        
        # Sprawdź inne elementy
        for keyword in data['keywords']['keyword']:
            name = keyword['name']
            count = keyword['count']
            
            if name == '/AcroForm' and count > 0:
                content_binary['forms'] = 1
            elif name == '/Encrypt' and count > 0:
                risk_score += 3
                warnings.append("PDF jest zaszyfrowany")
                content_binary['encryption'] = 1
            elif name == 'obj' and count > 1000:
                risk_score += 5
                warnings.append(f"Duża liczba obiektów: {count}")
                content_binary['large_objects'] = 1
        
        # Convert binary analysis to string
        binary_string = ''.join([
            str(content_binary['javascript']),
            str(content_binary['actions']),
            str(content_binary['launch']),
            str(content_binary['embedded']),
            str(content_binary['forms']),
            str(content_binary['encryption']),
            str(content_binary['large_objects']),
            str(content_binary['xfa'])
        ])
        
        # Generate error code based on binary analysis
        binary_int = int(binary_string, 2) if binary_string != '00000000' else 0
        error_code = f"PDF-{binary_int:03d}"
        
        # Determine safety level - bez uwzględniania linków
        if risk_score == 0:
            safety_level = "SAFE"
        elif risk_score <= 10:
            safety_level = "LOW_RISK"
        elif risk_score <= 40:
            safety_level = "MEDIUM_RISK"
        else:
            safety_level = "HIGH_RISK"
        
        # KROK 3: Ekstrakcja linków tylko dla bezpiecznych plików
        links = []
        suspicious_links_count = 0
        
        if metadata_check['safe_to_open']:
            try:
                links = extract_links_from_pdf(file_path)
                suspicious_links_count = sum(1 for link in links if link['suspicious'])
                
                if len(links) > 0:
                    if suspicious_links_count > 0:
                        warnings.append(f"Wykryto {len(links)} linków, w tym {suspicious_links_count} podejrzanych.")
                    else:
                        warnings.append(f"Wykryto {len(links)} linków - zachowaj ostrożność przy ich otwieraniu.")
            except Exception as e:
                logging.error(f"Error during safe link extraction: {str(e)}")
                warnings.append("Nie można było przeanalizować linków ze względów bezpieczeństwa")
        else:
            warnings.append("Analiza linków pominięta ze względów bezpieczeństwa")
        
        # Łagodniejsze ostrzeżenie dla bezpiecznych plików z linkami
        if len(links) > 0 and safety_level == "SAFE":
            warnings.append("Dokument zawiera linki - sprawdź je przed kliknięciem.")
        
        # Określ, czy PDF jest bezpieczny do podglądu
        preview_safe = metadata_check['safe_to_open']
        preview_unsafe_reasons = []
        
        if not preview_safe:
            if dangerous_elements.get('javascript', 0) > 0:
                preview_unsafe_reasons.append("Zawiera JavaScript")
            if dangerous_elements.get('actions', 0) > 0:
                preview_unsafe_reasons.append("Zawiera akcje automatyczne")
            if dangerous_elements.get('launch', 0) > 0:
                preview_unsafe_reasons.append("Zawiera akcje uruchamiania")
            if dangerous_elements.get('embedded', 0) > 0:
                preview_unsafe_reasons.append("Zawiera osadzone pliki")
            if dangerous_elements.get('xfa', 0) > 0:
                preview_unsafe_reasons.append("Zawiera formularze XFA")
        
        return {
            'is_pdf': data['isPdf'] == 'True',
            'safety_level': safety_level,
            'risk_score': risk_score,
            'warnings': warnings,
            'header': data['header'],
            'keywords': data['keywords']['keyword'],
            'content_binary_code': binary_string,
            'content_analysis': content_binary,
            'error_code': error_code,
            'analysis_complete': True,
            'error': None,
            'links': links,
            'links_count': len(links),
            'suspicious_links_count': suspicious_links_count,
            'preview_safe': preview_safe,
            'preview_unsafe_reasons': preview_unsafe_reasons,
            'safe_to_open': metadata_check['safe_to_open']
        }
        
    except Exception as e:
        logging.error(f"Error analyzing PDF: {str(e)}")
        return {
            'is_pdf': False,
            'safety_level': 'ERROR',
            'risk_score': -1,
            'warnings': ['Analiza nie powiodła się'],
            'content_binary_code': '11111111',
            'error_code': 'PDF-ERR',
            'analysis_complete': False,
            'error': str(e),
            'links': [],
            'links_count': 0,
            'suspicious_links_count': 0,
            'preview_safe': False,
            'preview_unsafe_reasons': ['Analiza nie powiodła się'],
            'safe_to_open': False
        }


def generate_pdf_preview(file_path, max_pages=3):
    """Generuje podgląd PDF jako listę zakodowanych obrazów w base64"""
    images = []
    doc = None
    try:
        if not os.path.exists(file_path):
            return {'success': False, 'error': 'Nie znaleziono pliku'}
        
        # KRYTYCZNE: Sprawdź bezpieczeństwo przed otwarciem
        metadata_check = analyze_pdf_safety_metadata_only(file_path)
        if not metadata_check['safe_to_open']:
            dangerous = [k for k, v in metadata_check['dangerous_elements'].items() if v > 0]
            return {
                'success': False, 
                'error': f'Plik zawiera niebezpieczne elementy: {", ".join(dangerous)}',
                'security_block': True
            }
            
        doc = fitz.open(file_path)
        total_pages = min(max_pages, len(doc))
        
        for page_num in range(total_pages):
            page = doc[page_num]
            # Renderuj stronę jako obraz (zwiększony zoom dla lepszej jakości)
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
            
            # Konwersja do formatu PNG
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            img_buffer = BytesIO()
            img.save(img_buffer, format="PNG")
            img_buffer.seek(0)
            
            # Kodowanie do base64
            img_str = base64.b64encode(img_buffer.read()).decode('utf-8')
            images.append({
                'data': f'data:image/png;base64,{img_str}',
                'page': page_num + 1,
                'width': pix.width,
                'height': pix.height
            })
        
        return {'success': True, 'images': images, 'total_pages': len(doc)}
    
    except Exception as e:
        logging.error(f"Error generating PDF preview: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        if doc:
            try:
                doc.close()
            except:
                pass

limiter = Limiter(key_func=lambda: request.remote_addr)
limiter.init_app(app)
@app.route('/')
def index():
    return render_template('index.html')


@limiter.limit("10 per minute")
@app.route('/api/analyze', methods=['POST'])
def analyze_pdf():
    """Main endpoint for PDF analysis"""
    if 'file' not in request.files:
        return jsonify({'error': translate_message('No file provided')}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': translate_message('No file selected')}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': translate_message('Only PDF files are allowed')}), 400
    
    # Generate unique filename
    unique_id = str(uuid.uuid4())
    filename = secure_filename(file.filename)
    temp_filename = f"{unique_id}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    
    try:
        # Save uploaded file
        file.save(file_path)
        logging.info(f"Analyzing file: {filename} (ID: {unique_id})")
        
        # Analyze PDF immediately
        result = analyze_pdf_safety(file_path)
        result['filename'] = filename
        result['analysis_id'] = unique_id
        result['timestamp'] = datetime.now().isoformat()
        
        # Log result
        logging.info(f"Analysis complete for {filename}: {result['safety_level']}")
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Error processing file {filename}: {str(e)}")
        return jsonify({'error': translate_message('File processing failed')}), 500
        
    finally:
        # CRITICAL: Securely delete the uploaded file immediately after analysis
        if os.path.exists(file_path):
            secure_delete_file(file_path)
            logging.info(f"Uploaded file securely removed: {temp_filename}")

@app.route('/api/pdf-preview', methods=['POST'])
def pdf_preview():
    """Endpoint do generowania podglądu PDF"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': translate_message('No file provided')}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': translate_message('No file selected')}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': translate_message('Only PDF files are allowed')}), 400
    
    # Generate unique filename
    unique_id = str(uuid.uuid4())
    filename = secure_filename(file.filename)
    temp_filename = f"{unique_id}_preview_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    
    try:
        # Save uploaded file
        file.save(file_path)
        logging.info(f"Generating preview for: {filename} (ID: {unique_id})")
        
        # Najpierw sprawdź bezpieczeństwo pliku
        safety_check = analyze_pdf_safety(file_path)
        
        # Jeśli plik nie jest bezpieczny do podglądu, zwróć błąd
        if not safety_check['preview_safe']:
            reasons = ", ".join(safety_check['preview_unsafe_reasons'])
            return jsonify({
                'success': False, 
                'error': f'Podgląd niedostępny ze względów bezpieczeństwa: {reasons}',
                'safety_level': safety_check['safety_level'],
                'unsafe_reasons': safety_check['preview_unsafe_reasons']
            }), 403
        
        # Jeśli plik jest bezpieczny, generuj podgląd
        preview_result = generate_pdf_preview(file_path, max_pages=3)
        
        if preview_result['success']:
            return jsonify(preview_result)
        else:
            return jsonify({'success': False, 'error': 'Nie udało się wygenerować podglądu: ' + preview_result.get('error', 'Nieznany błąd')}), 500
        
    except Exception as e:
        logging.error(f"Error processing preview for {filename}: {str(e)}")
        return jsonify({'success': False, 'error': translate_message('File processing failed') + f": {str(e)}"}), 500
        
    finally:
        # CRITICAL: Securely delete the uploaded file immediately after processing
        if os.path.exists(file_path):
            secure_delete_file(file_path)
            logging.info(f"Preview file securely removed: {temp_filename}")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@limiter.limit("5 per minute")
@app.route('/api/virustotal-check', methods=['POST'])
def virustotal_check():
    """Endpoint do sprawdzania linków przez VirusTotal"""
    try:
        data = request.get_json()
        if not data or 'links' not in data:
            logging.warning("VirusTotal check: No links provided in request")
            return jsonify({'error': 'Brak linków do sprawdzenia'}), 400
        
        links = data['links']
        if not isinstance(links, list) or len(links) == 0:
            logging.warning("VirusTotal check: Empty links list")
            return jsonify({'error': 'Lista linków jest pusta'}), 400
        
        if len(links) > 10:  # Limit dla bezpieczeństwa
            logging.warning(f"VirusTotal check: Too many links requested: {len(links)}")
            return jsonify({'error': 'Można sprawdzić maksymalnie 10 linków jednocześnie'}), 400
        
        # Inicjalizuj VirusTotal API
        vt_api = get_virustotal_api()
        
        if not vt_api.is_configured():
            logging.error("VirusTotal API not configured")
            return jsonify({
                'error': 'VirusTotal API nie jest skonfigurowany',
                'message': 'Skontaktuj się z administratorem systemu w celu konfiguracji API VirusTotal'
            }), 503
        
        # Sprawdź linki
        results = []
        total_checked = 0
        
        for link_data in links:
            try:
                url = link_data.get('url') if isinstance(link_data, dict) else str(link_data)
                
                # Sprawdź tylko HTTP/HTTPS linki
                if not url.startswith(('http://', 'https://')):
                    results.append({
                        'url': url,
                        'status': 'skipped',
                        'message': 'Pominięto - nie jest to link HTTP/HTTPS'
                    })
                    logging.info(f"Skipping non-HTTP(S) URL: {url}")
                    continue
                
                logging.info(f"Checking URL with VirusTotal: {url}")
                result = vt_api.analyze_url(url, wait_for_results=True, max_wait_time=30)
                results.append(result)
                total_checked += 1
                
                # Dodaj opóźnienie między zapytaniami
                if total_checked < len([l for l in links if str(l).startswith(('http://', 'https://'))]):
                    time.sleep(0.5)
                    
            except Exception as e:
                logging.error(f"Error checking individual URL {url}: {str(e)}")
                results.append({
                    'url': url,
                    'status': 'error',
                    'error': f'Błąd podczas sprawdzania: {str(e)}'
                })
        
        logging.info(f"VirusTotal check completed: {total_checked} URLs checked")
        
        return jsonify({
            'success': True,
            'results': results,
            'total_checked': total_checked,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error in VirusTotal check: {str(e)}")
        return jsonify({'error': f'Błąd podczas sprawdzania: {str(e)}'}), 500

# Cleanup function for any leftover files (run on startup)
def cleanup_temp_files():
    """Clean up any temporary files left from previous sessions"""
    try:
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.isfile(file_path):
                    secure_delete_file(file_path)
                    logging.info(f"Cleaned up leftover file: {filename}")
    except Exception as e:
        logging.error(f"Error during cleanup: {str(e)}")

# Development server configuration
if __name__ == '__main__':
    print("Starting PDF Analyzer Server...")
    print(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"Log file: {log_file}")
    
    # Clean up any leftover files from previous runs
    cleanup_temp_files()
    
    print("Server will be available at: http://localhost:5000")
    print("Note: Files are securely deleted after analysis")
    app.run(host='0.0.0.0', port=5000, debug=False)
