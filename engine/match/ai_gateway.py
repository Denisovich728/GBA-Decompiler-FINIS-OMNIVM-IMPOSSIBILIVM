"""Gestor seguro de credenciales y proveedores de IA (Ollama, OpenAI, Anthropic, Google Gemini, Custom).

Cifra las API Keys localmente mediante AES-256 (Fernet) ligada a una clave de máquina/usuario
para no dejar nunca tokens o llaves en texto plano en disco.
"""
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path

from cryptography.fernet import Fernet
import requests

from common import TREE_DIR

CREDENTIALS_FILE = TREE_DIR / "credentials_vault.enc"
CONFIG_FILE = TREE_DIR / "engine_config.json"


def _get_machine_key() -> bytes:
    """Genera una clave determinista derivada del hardware/usuario de la maquina para el cifrado AES."""
    machine_id = str(uuid.getnode()) + os.environ.get("USERNAME", "Denisovich728") + "FOMT_CYBER_VAULT_SALT_2026"
    h = hashlib.sha256(machine_id.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(h)


def load_vault() -> dict:
    """Carga y descifra el baúl de credenciales."""
    if not CREDENTIALS_FILE.exists():
        return {}
    try:
        f = Fernet(_get_machine_key())
        data = CREDENTIALS_FILE.read_bytes()
        decrypted = f.decrypt(data)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        return {}


def save_vault(vault: dict):
    """Cifra con AES-256 y guarda el baúl de credenciales de forma atómica."""
    TREE_DIR.mkdir(parents=True, exist_ok=True)
    f = Fernet(_get_machine_key())
    raw = json.dumps(vault, indent=2).encode("utf-8")
    encrypted = f.encrypt(raw)
    tmp = CREDENTIALS_FILE.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    tmp.replace(CREDENTIALS_FILE)


def set_provider_credential(provider: str, api_key: str, base_url: str = "", model: str = ""):
    vault = load_vault()
    if provider not in vault:
        vault[provider] = {}
    if api_key is not None:
        vault[provider]["api_key"] = api_key
    if base_url:
        vault[provider]["base_url"] = base_url
    if model:
        vault[provider]["model"] = model
    save_vault(vault)


def get_provider_credential(provider: str) -> dict:
    vault = load_vault()
    return vault.get(provider, {})


def call_unified_llm(messages: list, provider: str, model: str, temperature: float = 0.1, max_tokens: int = 700, quiet: bool = True, num_ctx: int = 6144, threads: int = 8) -> str:
    """Llamador polimórfico universal de IA con soporte para Ollama, OpenAI, Anthropic, Google Gemini y Custom REST."""
    cred = get_provider_credential(provider)
    api_key = cred.get("api_key", "")
    base_url = cred.get("base_url", "")

    # 1. OLLAMA LOCAL
    if provider == "ollama":
        url = base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434/api/chat")
        opts = {
            "temperature": temperature,
            "top_p": 0.80,
            "top_k": 20,
            "num_ctx": num_ctx,
            "num_predict": max_tokens,
            "repeat_penalty": 1.03,
            "num_thread": threads,
            "stop": ["\nExplicación", "\nExplanation", "\nEn este", "\nNota:", "\n###"],
        }
        r = requests.post(
            url,
            json={"model": model, "messages": messages, "stream": False, "options": opts, "keep_alive": "15m"},
            timeout=1800,
        )
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")

    # 2. OPENAI (GPT-4o, o1, etc.)
    elif provider == "openai":
        url = (base_url.rstrip("/") if base_url else "https://api.openai.com/v1") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model or "gpt-4o",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=120)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    # 3. ANTHROPIC (Claude 3.5 Sonnet, etc.)
    elif provider == "anthropic":
        url = (base_url.rstrip("/") if base_url else "https://api.anthropic.com/v1") + "/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        system_prompt = ""
        user_msgs = []
        for m in messages:
            if m["role"] == "system":
                system_prompt += m["content"] + "\n"
            else:
                user_msgs.append({"role": m["role"], "content": m["content"]})
        payload = {
            "model": model or "claude-3-5-sonnet-20241022",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_prompt.strip(),
            "messages": user_msgs,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=120)
        r.raise_for_status()
        return r.json()["content"][0]["text"]

    # 4. GOOGLE GEMINI (Gemini 1.5 Pro, Flash)
    elif provider == "google":
        model_name = model or "gemini-1.5-pro"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        gemini_contents = []
        system_instruction = None
        for m in messages:
            if m["role"] == "system":
                system_instruction = {"parts": [{"text": m["content"]}]}
            else:
                role = "user" if m["role"] == "user" else "model"
                gemini_contents.append({"role": role, "parts": [{"text": m["content"]}]})
        payload = {
            "contents": gemini_contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            }
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction
        r = requests.post(url, json=payload, timeout=120)
        r.raise_for_status()
        data = r.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    # 5. CUSTOM REST (OpenAI-compatible endpoint como LocalAI, vLLM, LMStudio, etc.)
    elif provider == "custom":
        url = (base_url.rstrip("/") if base_url else "http://localhost:8000/v1") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": model or "custom-model",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=180)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    else:
        raise ValueError(f"Proveedor de IA desconocido o no configurado: {provider}")

