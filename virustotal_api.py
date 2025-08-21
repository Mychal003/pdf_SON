import requests
import time
import logging
from urllib.parse import urlparse
import base64
import hashlib

class VirusTotalAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'x-apikey': self.api_key,
                'User-Agent': 'PDF-Analyzer/1.0'
            })
    
    def is_configured(self):
        """Sprawdza czy API key jest skonfigurowany"""
        return self.api_key is not None and len(self.api_key) > 0
    
    def get_url_id(self, url):
        """Generuje ID URL dla VirusTotal API"""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return url_id
    
    def submit_url(self, url):
        """Przesyła URL do analizy w VirusTotal"""
        if not self.is_configured():
            return {'error': 'VirusTotal API key nie jest skonfigurowany'}
        
        try:
            data = {'url': url}
            response = self.session.post(f"{self.base_url}/urls", data=data)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                return {'error': 'Przekroczono limit zapytań API', 'retry_after': response.headers.get('Retry-After')}
            else:
                return {'error': f'Błąd API: {response.status_code}', 'details': response.text}
                
        except Exception as e:
            logging.error(f"Error submitting URL to VirusTotal: {str(e)}")
            return {'error': f'Błąd połączenia: {str(e)}'}
    
    def get_url_report(self, url):
        """Pobiera raport analizy URL z VirusTotal"""
        if not self.is_configured():
            return {'error': 'VirusTotal API key nie jest skonfigurowany'}
        
        try:
            url_id = self.get_url_id(url)
            response = self.session.get(f"{self.base_url}/urls/{url_id}")
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'error': 'URL nie został jeszcze przeanalizowany', 'not_found': True}
            elif response.status_code == 429:
                return {'error': 'Przekroczono limit zapytań API', 'retry_after': response.headers.get('Retry-After')}
            else:
                return {'error': f'Błąd API: {response.status_code}', 'details': response.text}
                
        except Exception as e:
            logging.error(f"Error getting URL report from VirusTotal: {str(e)}")
            return {'error': f'Błąd połączenia: {str(e)}'}
    
    def analyze_url(self, url, wait_for_results=True, max_wait_time=60):
        """Analizuje URL - przesyła i czeka na wyniki lub pobiera istniejący raport"""
        if not self.is_configured():
            logging.warning("VirusTotal API not configured")
            return {
                'url': url,
                'status': 'error',
                'error': 'VirusTotal API key nie jest skonfigurowany'
            }
        
        try:
            logging.debug(f"Starting analysis for URL: {url}")
            
            # Najpierw sprawdź czy URL już był analizowany
            report = self.get_url_report(url)
            
            if 'error' not in report:
                # URL już był analizowany, zwróć wyniki
                logging.debug(f"Found existing report for URL: {url}")
                return self.parse_report(url, report)
            elif report.get('not_found'):
                # URL nie był analizowany, prześlij do analizy
                logging.info(f"Submitting new URL for analysis: {url}")
                submission = self.submit_url(url)
                
                if 'error' in submission:
                    logging.error(f"Failed to submit URL {url}: {submission['error']}")
                    return {
                        'url': url,
                        'status': 'error',
                        'error': submission['error']
                    }
                
                if not wait_for_results:
                    return {
                        'url': url,
                        'status': 'submitted',
                        'message': 'URL przesłany do analizy'
                    }
                
                # Czekaj na wyniki
                logging.info(f"Waiting for analysis results for URL: {url}")
                wait_time = 0
                while wait_time < max_wait_time:
                    time.sleep(5)  # Czekaj 5 sekund
                    wait_time += 5
                    
                    report = self.get_url_report(url)
                    if 'error' not in report:
                        logging.info(f"Got analysis results for URL: {url}")
                        return self.parse_report(url, report)
                    elif not report.get('not_found'):
                        # Inny błąd niż "not found"
                        logging.error(f"Error getting report for URL {url}: {report['error']}")
                        return {
                            'url': url,
                            'status': 'error',
                            'error': report['error']
                        }
                
                # Timeout
                logging.warning(f"Timeout waiting for analysis results for URL: {url}")
                return {
                    'url': url,
                    'status': 'timeout',
                    'message': 'Przekroczono czas oczekiwania na wyniki'
                }
            else:
                # Inny błąd
                logging.error(f"Error checking URL {url}: {report['error']}")
                return {
                    'url': url,
                    'status': 'error',
                    'error': report['error']
                }
                
        except Exception as e:
            logging.error(f"Exception in analyze_url for {url}: {str(e)}")
            return {
                'url': url,
                'status': 'error',
                'error': f'Błąd analizy: {str(e)}'
            }
    
    def parse_report(self, url, report):
        """Parsuje raport z VirusTotal do czytelnego formatu"""
        try:
            data = report.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            clean = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            timeout = stats.get('timeout', 0)
            
            total_scanners = malicious + suspicious + clean + undetected + timeout
            
            # Określ status na podstawie wyników
            if malicious > 0:
                status = 'malicious'
                threat_level = 'high'
            elif suspicious > 0:
                status = 'suspicious'
                threat_level = 'medium'
            elif clean > 0:
                status = 'clean'
                threat_level = 'low'
            else:
                status = 'unknown'
                threat_level = 'unknown'
            
            # Pobierz informacje o wykrytych zagrożeniach
            results = attributes.get('last_analysis_results', {})
            detections = []
            
            for engine, result in results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'category': result.get('category'),
                        'result': result.get('result'),
                        'method': result.get('method')
                    })
            
            return {
                'url': url,
                'status': status,
                'threat_level': threat_level,
                'stats': {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'clean': clean,
                    'undetected': undetected,
                    'timeout': timeout,
                    'total': total_scanners
                },
                'detections': detections,
                'scan_date': attributes.get('last_analysis_date'),
                'first_submission_date': attributes.get('first_submission_date'),
                'times_submitted': attributes.get('times_submitted', 0),
                'reputation': attributes.get('reputation', 0)
            }
            
        except Exception as e:
            logging.error(f"Error parsing VirusTotal report: {str(e)}")
            return {
                'url': url,
                'status': 'error',
                'error': f'Błąd parsowania raportu: {str(e)}'
            }
    
    def analyze_multiple_urls(self, urls, max_concurrent=5):
        """Analizuje wiele URLi jednocześnie"""
        if not self.is_configured():
            return [{
                'url': url,
                'status': 'error',
                'error': 'VirusTotal API key nie jest skonfigurowany'
            } for url in urls]
        
        results = []
        
        # Analizuj URLs w partiach, aby nie przekroczyć limitów API
        for i in range(0, len(urls), max_concurrent):
            batch = urls[i:i + max_concurrent]
            
            for url in batch:
                result = self.analyze_url(url, wait_for_results=False)
                results.append(result)
                
                # Dodaj opóźnienie między zapytaniami
                time.sleep(0.2)
        
        return results

def get_virustotal_api():
    """Factory function do tworzenia instancji VirusTotal API"""
    # Możesz ustawić API key przez zmienną środowiskową lub plik konfiguracyjny
    import os
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    
    # Alternatywnie, możesz odczytać z pliku config
    if not api_key:
        try:
            config_path = os.path.join(os.path.dirname(__file__), 'config', 'virustotal_key.txt')
            with open(config_path, 'r') as f:
                content = f.read().strip()
                # Ignoruj linie zaczynające się od # (komentarze)
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        api_key = line
                        break
        except FileNotFoundError:
            logging.warning("VirusTotal API key not found. Create config/virustotal_key.txt or set VIRUSTOTAL_API_KEY environment variable.")
        except Exception as e:
            logging.error(f"Error reading VirusTotal API key from file: {str(e)}")
    
    if api_key:
        logging.info("VirusTotal API configured successfully")
    else:
        logging.warning("VirusTotal API not configured - no API key found")
    
    return VirusTotalAPI(api_key)
