"""Finds names and places in text, in five EU languages.

The gateway sends text to POST /analyze. This service first works out
which language the text is in, then runs that language's model: a German
model reads "Herr Jürgen Müller aus München" correctly, an English model
calls "München" a person. Running every model and merging the results
would be wrong, so the language comes first.

Offsets in the answer count characters (Unicode code points), as Python
does. The gateway converts them to byte offsets.
"""

import os

from flask import Flask, jsonify, request
from lingua import Language, LanguageDetectorBuilder
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

# Language code -> spaCy model. Add a language here and in the Dockerfile.
MODELS = {
    "de": "de_core_news_md",
    "en": "en_core_web_md",
    "fr": "fr_core_news_md",
    "es": "es_core_news_md",
    "it": "it_core_news_md",
}
LINGUA = {
    Language.GERMAN: "de",
    Language.ENGLISH: "en",
    Language.FRENCH: "fr",
    Language.SPANISH: "es",
    Language.ITALIAN: "it",
}

# The only entity types we report: the ones patterns can't find.
ENTITIES = ["PERSON", "LOCATION"]

# Used when the text is too short to tell its language ("Jürgen Müller").
DEFAULT_LANGUAGE = os.environ.get("NER_DEFAULT_LANGUAGE", "en")
MIN_SCORE = float(os.environ.get("NER_MIN_SCORE", "0.5"))
MAX_CHARS = 100_000

nlp_engine = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": code, "model_name": name} for code, name in MODELS.items()],
}).create_engine()
analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=list(MODELS))
detector = LanguageDetectorBuilder.from_languages(*LINGUA).build()

app = Flask(__name__)


def detect_language(text: str) -> str:
    lang = detector.detect_language_of(text)
    return LINGUA.get(lang, DEFAULT_LANGUAGE)


@app.post("/analyze")
def analyze():
    body = request.get_json(silent=True) or {}
    text = body.get("text")
    if not isinstance(text, str):
        return jsonify(error='body must be {"text": "..."}'), 400
    if len(text) > MAX_CHARS:
        return jsonify(error=f"text longer than {MAX_CHARS} characters"), 413

    language = body.get("language") or detect_language(text)
    if language not in MODELS:
        return jsonify(error=f"unsupported language {language!r}"), 400

    results = analyzer.analyze(text=text, language=language, entities=ENTITIES,
                               score_threshold=MIN_SCORE)
    entities = sorted(
        ({"type": r.entity_type, "start": r.start, "end": r.end, "score": round(r.score, 2)}
         for r in results),
        key=lambda e: e["start"],
    )
    return jsonify(language=language, entities=entities)


@app.get("/health")
def health():
    return jsonify(status="ok", languages=list(MODELS))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "3000")))