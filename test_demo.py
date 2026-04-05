import urllib.request
import json

try:
    url = 'http://127.0.0.1:8000/api/demo/start'
    data = json.dumps({'duration': 10, 'batch_size': 5}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as response:
        print('Demo started:', response.read().decode())
except Exception as e:
    print('Error:', e)