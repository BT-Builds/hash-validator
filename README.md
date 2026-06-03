# Hash Validator API

Compute and verify cryptographic hashes for any text input. Supports MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512, BLAKE2b, and BLAKE2s.

## Endpoints

### Health Check
```
GET /health
```
Returns service status. No API key required.

### Compute All Common Hashes
```
POST /api/v1/hash
Authorization: Bearer sk_your_api_key
Content-Type: application/json

{"text": "hello world"}
```

### Compute Specific Hash
```
POST /api/v1/hash/{algorithm}
Authorization: Bearer sk_your_api_key
Content-Type: application/json

{"text": "hello world"}
```
Supported: `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_512`, `blake2b`, `blake2s`

### Verify Hash
```
POST /api/v1/hash/verify
Authorization: Bearer sk_your_api_key
Content-Type: application/json

{"text": "hello world", "expected_hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "algorithm": "sha256"}
```

### Compute HMAC
```
POST /api/v1/hmac
Authorization: Bearer sk_your_api_key
Content-Type: application/json

{"text": "message", "key": "secret", "algorithm": "sha256"}
```

### Batch Hash (Multiple Algorithms)
```
POST /api/v1/hash/batch?algorithms=md5,sha256
Authorization: Bearer sk_your_api_key
Content-Type: application/json

{"text": "hello world"}
```

## Example Response
```json
{
  "input": "hello world",
  "hashes": {
    "md5": "5eb63bbbe01eeed093cb22bb8f73b885",
    "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    "sha512": "2c9f2a...e3b8"
  }
}
```

## Rate Limiting
100 requests per minute per API key.

## Monetization
List on RapidAPI for $19/month developer plan. Target: developers, DevOps engineers, security tools.