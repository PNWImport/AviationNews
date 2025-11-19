#!/usr/bin/env python3
"""Quick validation test"""
import requests
import time

print('Testing input validation...\n')

# Test 1: Long input
print('1. Testing length validation (100k chars)...')
r = requests.post('http://localhost:5001/api/ingest', json={'url': 'A'*100000})
print(f'   Status: {r.status_code}')
if r.status_code == 400:
    print(f'   ✓ PASS - {r.json()}')
else:
    print(f'   ✗ FAIL - Not rejected!')

# Test 2: Wrong type
print('\n2. Testing type validation (number instead of string)...')
r = requests.post('http://localhost:5001/api/ingest', json={'url': 12345})
print(f'   Status: {r.status_code}')
if r.status_code == 400:
    print(f'   ✓ PASS - {r.json()}')
else:
    print(f'   ✗ FAIL - Not rejected!')

# Test 3: Valid format but should fail URL validation
print('\n3. Testing normal flow (valid input format)...')
r = requests.post('http://localhost:5001/api/ingest', json={'url': 'https://example.com/feed.xml'})
print(f'   Status: {r.status_code}')
print(f'   Response: {str(r.json())[:100]}...')

print('\n✅ Validation tests complete!')
