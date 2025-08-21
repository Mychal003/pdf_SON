import os
import time
import logging
from datetime import datetime, timedelta

def secure_cleanup_old_files(upload_folder, max_age_minutes=5):
    """Clean up files older than specified age"""
    try:
        if not os.path.exists(upload_folder):
            return
            
        current_time = datetime.now()
        
        for filename in os.listdir(upload_folder):
            file_path = os.path.join(upload_folder, filename)
            if os.path.isfile(file_path):
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                if current_time - file_time > timedelta(minutes=max_age_minutes):
                    # Secure delete old file
                    file_size = os.path.getsize(file_path)
                    with open(file_path, 'r+b') as f:
                        f.write(b'\x00' * file_size)
                        f.flush()
                        os.fsync(f.fileno())
                    os.remove(file_path)
                    print(f"Cleaned up old file: {filename}")
                    
    except Exception as e:
        print(f"Cleanup error: {e}")

if __name__ == '__main__':
    upload_folder = os.path.join(os.getcwd(), 'temp_uploads')
    while True:
        secure_cleanup_old_files(upload_folder)
        time.sleep(300)  # Check every 5 minutes
