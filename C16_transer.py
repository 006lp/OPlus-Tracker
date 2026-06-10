# Designed by Jerry Tse
import sys
import base64
import json
import time
import hashlib
import argparse
import xml.etree.ElementTree as ET
from collections import OrderedDict
import requests
from datetime import datetime
import re
import os
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import urllib3

def format_as_android_pem(cert_pem):
    lines = cert_pem.strip().split('\n')
    base64_content = "".join([l.strip() for l in lines if not l.startswith('---')])
    return f"-----BEGIN CERTIFICATE-----\n{base64_content}-----END CERTIFICATE-----\n"

def sign_data(private_key_pem, data_json):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    signature = private_key.sign(
        data_json.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode()

def android_request(url, method='GET', data=None, headers=None, allow_redirects=False, timeout=30, max_retries=3):
    
    base_headers = {
        'userId': "oplus-ota|00000001",
        'Range': "bytes=0-",
    }
    
    if headers:
        base_headers.update(headers)
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=base_headers, timeout=timeout, allow_redirects=allow_redirects)
                
            print_request_info(url, method, base_headers, data, response)
            
            return response
            
        except requests.exceptions.Timeout as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Timeout")
                return None
                
        except requests.exceptions.ConnectionError as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Error")
                return None
                
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Failed")
                return None
    
    return None

def android_pre_request(url, method='GET', data=None, headers=None, allow_redirects=False, timeout=30, max_retries=3):

    tree = ET.parse("keybox.xml")
    root = tree.getroot()
    ec_key_node = root.find(".//Key[@algorithm='ecdsa']")
    private_key_pem = ec_key_node.find("PrivateKey").text.strip()
    cert_nodes = ec_key_node.findall(".//Certificate")
        
    android_pems = [format_as_android_pem(n.text.strip()) for n in cert_nodes]
    ac = base64.b64encode("".join(android_pems).encode()).decode()

    ts = str(int(time.time() * 1000))

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    target_id = query_params.get('g', [None])[0]
    hashed_id = target_id
        
    path_query = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
    signature_uri = path_query.lstrip("/").replace("=", ":")

    sign_payload = json.dumps(OrderedDict([
        ("id", hashed_id),
        ("ts", ts),
        ("uri", signature_uri)
        ]), separators=(',', ':'))
        
    as_sig = sign_data(private_key_pem, sign_payload)

    base_headers = {
        "ts": ts,
        "id": hashed_id,
        "userId": "oplus-ota|00000001",
        'Range': "bytes=0-",
        "ac": ac,
        "as": as_sig
    }
    
    if headers:
        base_headers.update(headers)
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=base_headers, timeout=timeout, allow_redirects=allow_redirects)
                
            print_request_info(url, method, base_headers, data, response)
            
            return response
            
        except requests.exceptions.Timeout as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Timeout")
                return None
                
        except requests.exceptions.ConnectionError as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Error")
                return None
                
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Failed")
                return None
    
    return None

def print_request_info(url, method, headers, data, response):
    
    print("=" * 50)
    print("Copyright (C) 2025-2026 Jerry Tse")
    print("=" * 50)
    print(f"URL: {url}")
    
    if response.status_code in [301, 302, 303, 307, 308]:
        redirect_url = response.headers.get('Location')

def parse_expires_time(url):

    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if "Expires" in url:
            expires_str = query_params.get('Expires', [None])[0]
            if not expires_str:
                return None

        elif "x-oss-expires" in url:
            expires_str = query_params.get('x-oss-expires', [None])[0]
            if not expires_str:
                return None

        expires_timestamp = int(expires_str)
        expires_time = datetime.fromtimestamp(expires_timestamp)
        current_time = datetime.now()
        
        return {
            'timestamp': expires_timestamp,
            'expires_time': expires_time
        }
    except Exception as e:
        print(f"❌ Cannot get expires: {e}")
        return None

def get_redirect_url(url):
    extra_headers = {}

    if "downloadCheck?" in url:
        response = android_request(url, 'GET', headers=extra_headers, allow_redirects=False, timeout=10, max_retries=3)
    elif "download?" in url:
        if os.path.isfile("keybox.xml"):
           response = android_pre_request(url, 'GET', headers=extra_headers, allow_redirects=False, timeout=10, max_retries=3)
        else:
            print("❌ Missing keybox.xml in current path")
            exit(1)
    
    if response and response.status_code == 302:
        redirect_url = response.headers.get('Location')
        
        time_info = parse_expires_time(redirect_url)
        
        print(f"\n✅ Success to resolve the URL:")
        print("=" * 50)
        print(redirect_url)
        print("=" * 50)
        
        if time_info:
            print(f"\n📅 Expire time(UTC+8): {time_info['expires_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        return redirect_url
    else:
        print("❌ Failed to resolve")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='C16 URL Transfer Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 %(prog)s <URL>
"""
    )
    parser.add_argument('url', help='URL to resolve')
    args = parser.parse_args()

    url = args.url

    redirect_url = get_redirect_url(url)
    
    if redirect_url:
        print("✅ DONE")
    else:
        print("❌ FAILED")
        exit(1)
