import re
import unicodedata

_NON_WORD = re.compile(r"[^a-z0-9]+")


def slugify(title: str, max_length: int = 80) -> str:
    """Превращает заголовок статьи в slug: латиница, цифры и дефисы."""
    normalized = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii")
    slug = _NON_WORD.sub("-", normalized.lower()).strip("-")
    return slug[:max_length].rstrip("-") or "article"
