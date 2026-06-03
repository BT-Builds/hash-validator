import hashlib
import hmac
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
from collections import defaultdict

app = FastAPI(title="Hash Validator API", version="1.0.0")
security = HTTPBearer(auto_error=False)

# Simple in-memory rate limiting
rate_limits = defaultdict(list)
RATE_LIMIT = 100  # requests per minute
RATE_WINDOW = 60

def check_rate_limit(api_key: str = None):
    if not api_key:
        return
    now = time.time()
    requests = rate_limits[api_key]
    rate_limits[api_key] = [t for t in requests if now - t < RATE_WINDOW]
    if len(rate_limits[api_key]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    rate_limits[api_key].append(now)

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Simple API key check - in production use proper key management
    if credentials and credentials.credentials and credentials.credentials.startswith("sk_"):
        return credentials.credentials
    return None

def get_hash_algorithm(name: str):
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "sha3_512": hashlib.sha3_512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }
    if name not in algorithms:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {name}")
    return algorithms[name]

class TextRequest(BaseModel):
    text: str

class VerifyRequest(BaseModel):
    text: str
    expected_hash: str
    algorithm: str = "sha256"

class HMACRequest(BaseModel):
    text: str
    key: str
    algorithm: str = "sha256"

class FileHashRequest(BaseModel):
    data: str  # base64 encoded or hex
    algorithm: str = "sha256"

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": time.time()}

@app.post("/api/v1/hash")
def compute_hash(request: TextRequest, api_key: str = Depends(verify_api_key)):
    check_rate_limit(api_key)
    results = {}
    for algo_name, algo_func in {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }.items():
        h = algo_func(request.text.encode()).hexdigest()
        results[algo_name] = h
    return {"input": request.text, "hashes": results, "algorithm": "all_common"}

@app.post("/api/v1/hash/verify")
def verify_hash(request: VerifyRequest, api_key: str = Depends(verify_api_key)):
    check_rate_limit(api_key)
    algo_func = get_hash_algorithm(request.algorithm)
    computed = algo_func(request.text.encode()).hexdigest()
    return {
        "text": request.text,
        "algorithm": request.algorithm,
        "expected": request.expected_hash,
        "computed": computed,
        "valid": hmac.compare_digest(computed.lower(), request.expected_hash.lower())
    }

@app.post("/api/v1/hash/{algorithm}")
def compute_specific_hash(algorithm: str, request: TextRequest, api_key: str = Depends(verify_api_key)):
    check_rate_limit(api_key)
    algo_func = get_hash_algorithm(algorithm)
    result = algo_func(request.text.encode()).hexdigest()
    return {"text": request.text, "algorithm": algorithm, "hash": result}

@app.post("/api/v1/hmac")
def compute_hmac(request: HMACRequest, api_key: str = Depends(verify_api_key)):
    check_rate_limit(api_key)
    algo_func = get_hash_algorithm(request.algorithm)
    result = hmac.new(request.key.encode(), request.text.encode(), algo_func).hexdigest()
    return {"text": request.text, "key": "***", "algorithm": request.algorithm, "hmac": result}

@app.post("/api/v1/hash/batch")
def batch_hash(request: TextRequest, algorithms: str = "md5,sha256,sha512", api_key: str = Depends(verify_api_key)):
    check_rate_limit(api_key)
    algo_list = [a.strip() for a in algorithms.split(",")]
    results = {}
    for algo in algo_list:
        try:
            algo_func = get_hash_algorithm(algo)
            results[algo] = algo_func(request.text.encode()).hexdigest()
        except HTTPException:
            results[algo] = {"error": "unsupported"}
    return {"input": request.text, "hashes": results}

try:
    from mangum import Mangum
    handler = Mangum(app, lifespan="off")
except ImportError:
    pass
