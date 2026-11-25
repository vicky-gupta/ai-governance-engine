FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# One spaCy model per language (about 40 MB each). Keep in sync with
# MODELS in app.py.
ARG SPACY_MODELS="de_core_news_md en_core_web_md fr_core_news_md es_core_news_md it_core_news_md"
RUN for m in $SPACY_MODELS; do \
      pip install --no-cache-dir "https://github.com/explosion/spacy-models/releases/download/$m-3.8.0/$m-3.8.0-py3-none-any.whl"; \
    done

COPY app.py test_app.py ./

EXPOSE 3000
# One worker: the models are loaded once (about 1 GB of memory); threads
# serve requests in parallel.
CMD ["gunicorn", "--bind", "0.0.0.0:3000", "--workers", "1", "--threads", "4", "--timeout", "60", "app:app"]