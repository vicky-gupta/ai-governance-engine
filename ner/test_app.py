"""Run with: pytest ner/  (needs the models installed, as in the Dockerfile)."""

from app import app

client = app.test_client()


def analyze(text, **extra):
    resp = client.post("/analyze", json={"text": text, **extra})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def found(result, text):
    return [(text[e["start"]:e["end"]], e["type"]) for e in result["entities"]]


def test_german_uses_the_german_model():
    text = "Herr Jürgen Müller aus München hat den Kredit beantragt."
    result = analyze(text)
    assert result["language"] == "de"
    assert ("Jürgen Müller", "PERSON") in found(result, text)
    assert ("München", "LOCATION") in found(result, text)


def test_other_languages():
    cases = {
        "en": "Please send the contract to John Smith in Manchester.",
        "fr": "Veuillez envoyer le contrat à Marie Dubois à Lyon.",
        "es": "Por favor, envíe el contrato a Carlos García en Sevilla.",
        "it": "Per favore invia il contratto a Giulia Rossi a Milano.",
    }
    for lang, text in cases.items():
        result = analyze(text)
        assert result["language"] == lang, text
        assert any(t == "PERSON" for _, t in found(result, text)), (lang, found(result, text))


def test_offsets_count_characters():
    # "ü" is one character here; the gateway turns it into two bytes.
    text = "Grüße an Jürgen Müller."
    result = analyze(text, language="de")
    assert ("Jürgen Müller", "PERSON") in found(result, text)


def test_bad_requests():
    assert client.post("/analyze", json={}).status_code == 400
    assert client.post("/analyze", json={"text": "hi", "language": "xx"}).status_code == 400