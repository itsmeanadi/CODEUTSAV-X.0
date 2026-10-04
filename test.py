import urllib.request, json  
req = urllib.request.Request('http://127.0.0.1:8000/api/agent/chat', data=json.dumps({'message': 'hello', 'protected': True, 'use_mock': False, 'provider': 'groq'}).encode(), headers={'Content-Type': 'application/json'})  
try: print(urllib.request.urlopen(req).read().decode())  
except Exception as e: print(e.read().decode())  
