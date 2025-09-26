import re
from datetime import datetime
import pytz

_ALLOWED_RE = re.compile(r"^[\w/\-\.]{1,50}$")

def sanitize_text(value: str) -> str:
    """Recorta y valida texto seguro con longitud 1–50 y charset limitado."""
    v = (value or "").strip()
    if not v or len(v) > 50 or not _ALLOWED_RE.match(v):
        raise ValueError("Valor inválido. Usa letras, números, guiones, guiones bajos, barras o puntos (1–50).")
    return v

def format_datetime_es(dt: datetime) -> str:
    return dt.strftime("%d/%m/%Y %H:%M")

def make_safe_filename(base: str) -> str:
    base = re.sub(r"[^\w\.-]+", "_", base.strip())
    return base[:128] if len(base) > 128 else base
