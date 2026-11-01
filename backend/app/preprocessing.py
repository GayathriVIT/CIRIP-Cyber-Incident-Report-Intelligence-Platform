"""Simple, dependency-light text preprocessing (no NLTK downloads required)."""
import re

STOPWORDS = set("""
a an the and or but if while is are was were be been being to of in on at by for with
from as this that these those it its it's he she they them his her their our your my
i we you not no nor do does did doing have has had having will would shall should can
could may might must about into over under again further then once here there when
where why how all any both each few more most other some such only own same so than
too very s t can will just don should now
""".split())


def clean_text(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    return text


def tokenize(text: str) -> list:
    return re.findall(r"[A-Za-z0-9\-\.]+", text.lower())


def normalize_for_model(text: str) -> str:
    """Cleaning used before feeding text into TF-IDF (kept mild on purpose so
    IoC-relevant tokens like IPs, hashes and CVEs are preserved for signal)."""
    text = clean_text(text)
    tokens = tokenize(text)
    tokens = [t for t in tokens if t not in STOPWORDS and len(t) > 1]
    return " ".join(tokens)
