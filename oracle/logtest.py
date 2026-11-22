#!/usr/bin/env python3
"""Send log lines to wazuh-logtest through the Wazuh server API.

Runs inside the Wazuh manager container, where Python and the API on
https://localhost:55000 are both available:

    docker exec -i -e WAZUH_API_PASSWORD rulelanes-oracle-manager \
        /var/ossec/framework/python/bin/python3 -c "$(cat oracle/logtest.py)" < lines.txt

(oracle/logtest.sh does this and reads the password from oracle/secrets.env.)

Reads one log line per stdin line and writes one JSON object per line to
stdout: {"event": <line>, "error": <int>, "alert": <bool>, "output": {...}}.
All lines share one logtest session; the session is closed at the end.
Uses only the documented endpoints PUT /logtest and
DELETE /logtest/sessions/{token}.

Credentials come from WAZUH_API_USER (default wazuh-wui) and
WAZUH_API_PASSWORD, which is required: there is no built-in password.
Written for rulelanes; GPL-3.0-only.
"""
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get('WAZUH_API_URL', 'https://localhost:55000')
USER = os.environ.get('WAZUH_API_USER', 'wazuh-wui')
PASSWORD = os.environ.get('WAZUH_API_PASSWORD')
if not PASSWORD:
    sys.exit('logtest.py: WAZUH_API_PASSWORD is not set')
LOG_FORMAT = os.environ.get('LOGTEST_LOG_FORMAT', 'syslog')
LOCATION = os.environ.get('LOGTEST_LOCATION', 'rulelanes')

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def request(method, path, token=None, body=None, basic=False):
    req = urllib.request.Request(API + path, method=method)
    if basic:
        cred = base64.b64encode((USER + ':' + PASSWORD).encode()).decode()
        req.add_header('Authorization', 'Basic ' + cred)
    else:
        req.add_header('Authorization', 'Bearer ' + token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header('Content-Type', 'application/json')
    # The API limits requests per minute (api.yaml
    # access.max_request_per_minute, 300 by default) and answers 429 above
    # it. Wait and retry rather than change the deployment's configuration.
    for _ in range(600):
        try:
            with urllib.request.urlopen(req, data=data, context=CTX, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
            time.sleep(1)
    raise RuntimeError('API rate limit did not clear')


def main():
    jwt = request('POST', '/security/user/authenticate?raw=true', basic=True).decode().strip()
    session = None
    out = sys.stdout
    for raw in sys.stdin.buffer:
        line = raw.decode('utf-8', errors='replace').rstrip('\r\n')
        body = {'event': line, 'log_format': LOG_FORMAT, 'location': LOCATION}
        if session:
            body['token'] = session
        resp = json.loads(request('PUT', '/logtest', token=jwt, body=body))
        data = resp.get('data', {})
        session = data.get('token', session)
        out.write(json.dumps({
            'event': line,
            'error': resp.get('error'),
            'alert': data.get('alert'),
            'messages': data.get('messages', []),
            'output': data.get('output'),
        }, sort_keys=True) + '\n')
        out.flush()
    if session:
        request('DELETE', '/logtest/sessions/' + session, token=jwt)


if __name__ == '__main__':
    main()
