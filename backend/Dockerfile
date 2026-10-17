FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

COPY requirements.txt .
# CPU-only PyTorch: the default wheel bundles gigabytes of CUDA libraries this server can't use.
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.14.1 \
 && pip install --no-cache-dir -r requirements.txt

# Phishing text model for the ml_phishing_text rule, baked into the image at build time:
# - pinned to an exact commit, so the model can't change under us;
# - safetensors weights only (pickle .bin files can run code when loaded);
# - no network access needed at runtime (HF_HUB_OFFLINE below).
ARG MODEL_REPO=cybersectony/phishing-email-detection-distilbert_v2.4.1
ARG MODEL_REVISION=6724dec17360ab1f6450553f1d950404f66a5dde
RUN python -c "from huggingface_hub import snapshot_download; snapshot_download('$MODEL_REPO', revision='$MODEL_REVISION', local_dir='models/phishing-distilbert', allow_patterns=['config.json', 'model.safetensors', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json', 'vocab.txt'])" \
 && rm -rf models/phishing-distilbert/.cache
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HOME=/tmp/hf

COPY app ./app
COPY config ./config
COPY data ./data

# Run as an unprivileged user.
RUN useradd --system --no-create-home appuser
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
