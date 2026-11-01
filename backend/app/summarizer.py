"""
Lightweight extractive summarization (TF-IDF sentence similarity + TextRank via
networkx), used as the DEFAULT summarizer so the project needs no external LLM
API key to run end-to-end.

If an LLM is configured (see llm_integration.py), main.py will prefer the
LLM-generated abstractive summary and clearly label it as such; otherwise it
falls back to this rule/ML-based extractive summary.
"""
import re
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def split_sentences(text: str):
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in sentences if len(s.strip()) > 0]


def extractive_summary(text: str, num_sentences: int = 3) -> str:
    sentences = split_sentences(text)
    if len(sentences) <= num_sentences:
        return text.strip()

    vectorizer = TfidfVectorizer(stop_words="english")
    try:
        X = vectorizer.fit_transform(sentences)
    except ValueError:
        return " ".join(sentences[:num_sentences])

    sim_matrix = cosine_similarity(X)
    graph = nx.from_numpy_array(sim_matrix)
    try:
        scores = nx.pagerank(graph)
    except nx.PowerIterationFailedConvergence:
        scores = {i: 1.0 for i in range(len(sentences))}

    ranked_idx = sorted(scores, key=scores.get, reverse=True)[:num_sentences]
    ranked_idx = sorted(ranked_idx)  # keep original order for readability
    return " ".join(sentences[i] for i in ranked_idx)
