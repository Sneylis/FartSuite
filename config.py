import os

AGENT_URL = os.getenv("AGENT_URL", "http://localhost:6669")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
