"""
Core data structure for the soul as a Merkle-Patricia Trie.
Implements the state transition protocol and local storage.
"""

import json
import time
import sqlite3
import threading
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import logging

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import cbor2

from firebase_admin import firestore, initialize_app, credentials
from google.cloud.firestore import Client as FirestoreClient

from config import FIREBASE_CREDENTIALS_PATH, FIREBASE_PROJECT_ID

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TransitionPayload:
    """Data structure for a state transition."""
    prev_hash: str
    timestamp: str
    delta: Dict[str, Any]
    nonce: int
    signature: Optional[bytes] = None

    def serialize(self) -> bytes:
        """Serialize the payload for signing or storage."""
        # Convert to dictionary, excluding signature
        data = asdict(self)
        data.pop('signature', None)
        return cbor2.dumps(data)

    def sign(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        """Sign the payload and store the signature."""
        data = self.serialize()
        self.signature = private_key.sign(data)

    def verify(self, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify the signature of the payload."""
        if self.signature is None:
            return False
        data = self.serialize()
        try:
            public_key.verify(self.signature, data)
            return True
        except InvalidSignature:
            return False

class Node:
    """Represents a node in the Merkle-Patricia Trie."""
    def __init__(self, path: str = "", value: Optional[Dict[str, Any]] = None, children: Dict[str, 'Node'] = None):
        self.path = path
        self.value = value if value is not None else {}
        self.children = children if children is not None else {}
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Compute the hash of the node."""
        # For simplicity, we use a hash of the path, value, and children hashes.
        # In a real Merkle-Patricia Trie, we would use a cryptographic hash function.
        # We'll use SHA256 for now.
        import hashlib
        data = self.path + json.dumps(self.value, sort_keys=True)
        for child_key in sorted(self.children.keys()):
            data += child_key + self.children[child_key].hash
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert the node to a dictionary for storage."""
        return {
            'path': self.path,
            'value': self.value,
            'children': {k: v.hash for k, v in self.children.items()},
            'hash': self.hash
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], all_nodes: Dict[str, 'Node']) -> 'Node':
        """Reconstruct a node from a dictionary and a map of all nodes by hash."""
        node = cls(path=data['path'], value=data['value'])
        node.hash = data['hash']
        # Reconstruct children from hashes
        for child_key, child_hash in data['children'].items():
            if child_hash in all_nodes:
                node.children[child_key] = all_nodes[child_hash]
            else:
                # If the child node is not in the map, we leave it as a hash and will load it later?
                # Alternatively, we can load all nodes recursively from Firestore.
                # For now, we'll leave it as a placeholder and expect the trie to be loaded fully.
                raise ValueError(f"Child node with hash {child_hash} not found in all_nodes.")
        return node

class SoulChain:
    """Manages the soul's state as a Merkle-Patricia Trie."""

    def __init__(self, identity_keypair: Optional[ed25519.Ed25519PrivateKey] = None):
        """
        Initialize the SoulChain.

        Args:
            identity_keypair: The Ed25519 keypair for the soul. If None, generate a new one.
        """
        # Cryptographic identity
        if identity_keypair is None:
            identity_keypair = ed25519.Ed25519PrivateKey.generate()
        self.private_key = identity_keypair
        self.public_key = identity_keypair.public_key()

        # The state trie
        self.root = Node(path="root")
        self.tip = self.root.hash  # Initially, the tip is the root hash

        # Firestore client
        cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
        self.firebase_app = initialize_app(cred, {'projectId': FIREBASE_PROJECT_ID})
        self.db: FirestoreClient = firestore.client()

        # Local SQLite cache
        self.local_db = sqlite3.connect('soulchain.db', check_same_thread=False)
        self._init_local_db()

        # Background audit daemon
        self.audit_daemon = threading.Thread(target=self._audit_loop, daemon=True)
        self.audit_daemon.start()

        logger.info("SoulChain initialized.")

    def _init_local_db(self):
        """Initialize the local SQLite database."""
        cursor = self.local_db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nodes (
                hash TEXT PRIMARY KEY,
                path TEXT,
                value TEXT,
                children TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transitions (
                hash TEXT PRIMARY KEY,
                payload BLOB,
                signature BLOB
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tip (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                hash TEXT
            )
        ''')
        # Insert initial tip if not exists
        cursor.execute('INSERT OR IGNORE INTO tip (id, hash) VALUES (0, ?)', (self.tip,))
        self.local_db.commit()

    def store_node(self, node: Node):
        """Store a node in Firestore and local cache."""
        # Store in Firestore
        node_ref = self.db.collection('nodes').document(node.hash)
        node_ref.set(node.to_dict())

        # Store in local SQLite
        cursor = self.local_db.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO nodes (hash, path, value, children) VALUES (?, ?, ?, ?)',
            (node.hash, node.path, json.dumps(node.value), json.dumps(list(node.children.keys())))
        )
        self.local_db.commit()

    def load_node(self, hash: str) -> Optional[Node]:
        """Load a node by hash from local cache or Firestore."""
        # Try local cache first
        cursor = self.local_db.cursor()
        cursor.execute('SELECT path, value, children FROM nodes WHERE hash = ?', (hash,))
        row = cursor.fetchone()
        if row:
            path, value_str, children_str = row
            value = json.loads(value_str)
            children_keys = json.loads(children_str)
            # We don't have the full children nodes, just their keys. We'll load them recursively.
            # For now, return a node with empty children and then load them when needed.
            node = Node(path=path, value=value)
            node.hash = hash
            # We'll load the children later if needed.
            return node

        # If not in local cache, try Firestore
        node_ref = self.db.collection('nodes').document(hash)
        node_doc = node_ref.get()
        if node_doc.exists:
            node_data = node_doc.to_dict()
            # We need to load all children nodes from Firestore recursively.
            # This is inefficient, so we might want to store the entire trie in one document?
            # Alternatively, we can load the node and then load its children when needed.
            node = Node.from_dict(node_data, {})  # We don't have the children nodes yet.
            # Store in local cache for future
            cursor.execute(
                'INSERT OR REPLACE INTO nodes (hash, path, value, children) VALUES (?, ?, ?, ?)',
                (hash, node.path, json.dumps(node.value), json.dumps(list(node.children.keys())))
            )
            self.local_db.commit()
            return node

        return None

    def make_transition(self, delta: Dict[str, Any]):
        """Create and append a new state transition to the trie."""
        # Create the transition payload
        nonce = int(time.time() * 1000)  # Simple nonce using timestamp
        payload = TransitionPayload(
            prev_hash=self.tip,
            timestamp=datetime.utcnow().isoformat(),
            delta=delta,
            nonce=nonce
        )
        payload.sign(self.private_key)

        # Create a new node for this transition
        # In a Merkle-Patricia Trie, we would insert the transition at a path determined by the hash.
        # For simplicity, we'll create a new node and link it as a child of the current tip.
        # This is not a standard trie insertion, but a simplified version.

        # Create a new node for the transition
        new_node = Node(path=payload.timestamp, value=payload.delta)
        new_node.hash = new_node.compute_hash()

        # Link the new node to the current tip node
        tip_node = self.load_node(self.tip)
        if tip_node is None:
            logger.error("Current tip node not found.")
            return

        # In a real trie, we would insert the node at a path. Here, we just add it as a child.
        # We use the new node's hash as the key in the children dictionary.
        tip_node.children[new_node.hash] = new_node
        tip_node.hash = tip_node.compute_hash()  # Update the tip node's hash

        # Update the tip to the new node's hash? Actually, we are building a chain, so the new node becomes the tip.
        # But note: we are adding the new node as a child of the old tip, so the old tip is still in the trie.
        # The new tip is the new node's hash? Or the old tip's hash? We'll set the tip to the new node's hash.
        self.tip = new_node.hash

        # Store the updated tip node and the new node
        self.store_node(tip_node)
        self.store_node(new_node)

        # Store the transition payload and signature in Firestore and local cache
        transition_ref = self.db.collection('transitions').document(new_node.hash)
        transition_ref.set({
            'payload': cbor2.dumps(asdict(payload)),
            'signature': payload.signature.hex() if payload.signature else None
        })

        cursor = self.local_db.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO transitions (hash, payload, signature) VALUES (?, ?, ?)',
            (new_node.hash, cbor2.dumps(asdict(payload)), payload.signature)
        )
        cursor.execute('UPDATE tip SET hash = ? WHERE id = 0', (self.tip,))
        self.local_db.commit()

        logger.info(f"New transition added with hash: {new_node.hash}")

    def _audit_loop(self):
        """Background loop to audit the trie's cryptographic consistency."""
        while True:
            time.sleep(60)  # Run every minute
            try:
                self.audit()
            except Exception as e:
                logger.error(f"Audit failed: {e}")

    def audit(self):
        """Audit the entire trie to ensure consistency."""
        # Load the tip node and walk back to the root, verifying each transition.
        current_hash = self.tip
        while current_hash != self.root.hash:
            node = self.load_node