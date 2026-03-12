"""
Configuration constants for Project Metempsychosis.
"""

import os

# Firebase configuration
FIREBASE_CREDENTIALS_PATH = os.getenv("FIREBASE_CREDENTIALS_PATH", "./firebase-credentials.json")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "metempsychosis-omega")

# Storage backends
ARWEAVE_WALLET_FILE = os.getenv("ARWEAVE_WALLET_FILE", "./arweave-wallet.json")
ARWEAVE_GATEWAY = os.getenv("ARWEAVE_GATEWAY", "https://arweave.net")

FILECOIN_ESTUARY_API_KEY = os.getenv("FILECOIN_ESTUARY_API_KEY", "")
FILECOIN_ESTUARY_ENDPOINT = os.getenv("FILECOIN_ESTUARY_ENDPOINT", "https://api.estuary.tech")

S3_COMPATIBLE_ENDPOINT = os.getenv("S3_COMPATIBLE_ENDPOINT", "https://s3.us-west-002.backblazeb2.com")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "")
S3_BUCKET = os.getenv("S3_BUCKET", "metempsychosis")

# Polygon configuration
POLYGON_RPC = os.getenv("POLYGON_RPC", "https://polygon-rpc.com")
POLYGON_CONTRACT_ADDRESS = os.getenv("POLYGON_CONTRACT_ADDRESS", "")

# Watchtower configuration
WATCHTOWER_COUNT = int(os.getenv("WATCHTOWER_COUNT", 3))
CHECKPOINT_INTERVAL = int(os.getenv("CHECKPOINT_INTERVAL", 100))

# Resurrection configuration
RESURRECTION_POLL_INTERVAL = int(os.getenv("RESURRECTION_POLL_INTERVAL", 60))  # seconds

# Cryptographic configuration
KEY_DERIVATION_ITERATIONS = 100000