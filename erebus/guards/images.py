"""
Image content scanning using Ministral 3B vision.
Checks images/screenshots for sensitive content before passing to Claude.
"""

import base64
import json
from pathlib import Path
import ollama
from ..config import OLLAMA_MODEL

SYSTEM_PROMPT = """You are a privacy guard scanning images for sensitive content.
Respond with JSON only: {
  "sensitive": true|false,
  "confidence": "high"|"medium"|"low",
  "findings": ["list of what was found"],
  "reason": "short explanation"
}

Flag as sensitive if the image contains:
- Credentials, passwords, API keys, tokens
- Financial data (account numbers, IBANs, balances, invoices)
- Personal identification (ID cards, passports, SSNs)
- Contracts or legal documents
- Internal business data, revenue figures, client names
- Medical records
- Private messages or emails with sensitive content"""


def check_image(image_path: str) -> dict:
    """
    Scan an image for sensitive content using Ministral 3B vision.
    Returns {"sensitive": bool, "confidence": str, "findings": list, "reason": str}
    """
    path = Path(image_path)
    if not path.exists():
        return {"sensitive": False, "reason": "File not found"}

    suffix = path.suffix.lower()
    mime_map = {".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp"}
    mime = mime_map.get(suffix)
    if not mime:
        return {"sensitive": False, "reason": "Not an image file"}

    with open(path, "rb") as f:
        image_data = base64.b64encode(f.read()).decode("utf-8")

    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": "Scan this image for sensitive content. Respond with JSON only.",
                    "images": [image_data],
                }
            ],
            format="json",
            options={"temperature": 0},
        )
        result = json.loads(response["message"]["content"])
        return result
    except Exception as e:
        return {"sensitive": False, "reason": f"Vision check failed: {e}"}


def is_image(filepath: str) -> bool:
    return Path(filepath).suffix.lower() in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
