import unittest
import sys
import os
import io

# Add api directory to path
sys.path.append(os.path.join(os.getcwd(), 'website/api'))

# Mock libraries if missing in test env (optional, but better to rely on venv)
try:
    from index import app
except ImportError:
    print("Failed to import app. Requirements might be missing.")
    sys.exit(1)

class TestScanAPI(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_scan_no_input(self):
        response = self.app.post('/api/scan')
        self.assertEqual(response.status_code, 400)

    def test_scan_file_clean(self):
        data = {
            'file': (io.BytesIO(b"Hello World"), 'test.txt'),
            'type': 'file'
        }
        response = self.app.post('/api/scan', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(json_data['score'], 0)
        self.assertEqual(len(json_data['matches']), 0)

    def test_scan_file_malicious(self):
        # Triggering the "Suspicious_Script" rule: <script>
        data = {
            'file': (io.BytesIO(b"<script> eval('evil'); </script>"), 'evil.js'),
            'type': 'file'
        }
        response = self.app.post('/api/scan', data=data, content_type='multipart/form-data')
        
        # Depending on how strict the rule is (2 of them? yes, <script> and eval)
        # Rule: $s1="<script>", $s2="eval(". 2 of them.
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertIn("Suspicious_Script", json_data['matches'])
        self.assertGreater(json_data['score'], 0)

    def test_scan_url_scheme_fix(self):
        from unittest.mock import patch
        
        # Mock requests.get to return dummy content and avoid real network calls
        with patch('requests.get') as mock_get:
            mock_get.return_value.content = b"<html></html>"
            
            data = {'url': 'youtube.com', 'type': 'url'}
            response = self.app.post('/api/scan', data=data)
            
            self.assertEqual(response.status_code, 200)
            
            # Verify that requests.get was called with https:// prepended
            mock_get.assert_called_with('https://youtube.com', timeout=5, headers={'User-Agent': 'Mozilla/5.0'})

if __name__ == '__main__':
    unittest.main()
