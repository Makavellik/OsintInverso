import requests
import socket
import ssl
import dns.resolver
import tldextract
import whois
import hashlib
import time
import random
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from functools import lru_cache
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text
import math
import threading

console = Console()
_stop_animation = False

# =========================
# CONTROL DE RITMO (ANTI-SCANNER)
# =========================

LAST_REQUEST = {}
GLOBAL_LAST = 0.0

def rate_limit(domain, delay=2.0, jitter=0.4, max_backoff=8.0):
    """
    Rate limit sigiloso y humano.
    - Per-domain
    - Global smoothing
    - Jitter anti-detección
    """

    try:
        now = time.monotonic()

        # =========================
        # GLOBAL SMOOTHING
        # =========================
        global GLOBAL_LAST
        global_delta = now - GLOBAL_LAST
        if global_delta < 0.3:
            time.sleep(0.3 - global_delta)

        # =========================
        # DOMAIN MEMORY
        # =========================
        last, hits = LAST_REQUEST.get(domain, (0.0, 0))
        delta = now - last

        # =========================
        # BACKOFF PROGRESIVO
        # =========================
        adaptive_delay = min(
            delay + (hits * 0.5),
            max_backoff
        )

        # =========================
        # ESPERA CONTROLADA
        # =========================
        if delta < adaptive_delay:
            sleep_time = adaptive_delay - delta
            sleep_time += random.uniform(0, jitter)
            time.sleep(sleep_time)

        # =========================
        # ACTUALIZACIÓN DE ESTADO
        # =========================
        LAST_REQUEST[domain] = (time.monotonic(), hits + 1)
        GLOBAL_LAST = time.monotonic()

    except Exception:
        # Silencio total: el flujo nunca se rompe
        pass


# =========================
# UTILIDADES
# =========================

def normalize_url(raw):
    """
    Normaliza entradas humanas reales:
    - dominios
    - URLs incompletas
    - IPs
    - esquemas raros
    - basura alrededor
    """
    if not raw:
        raise ValueError("URL vacía")

    url = raw.strip()

    # elimina espacios invisibles y errores comunes
    url = url.replace(" ", "")

    # si parece IP o dominio sin esquema
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # fallback defensivo
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Formato de URL inválido")
    except Exception:
        raise ValueError(f"No se pudo normalizar la URL: {raw}")

    return url

def extract_domain(url):
    """
    Extrae dominio real desde:
    - URLs completas
    - IPs
    - dominios raros
    - subdominios profundos
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or url

        # IP directa → se respeta
        try:
            socket.inet_aton(host)
            return host
        except Exception:
            pass

        ext = tldextract.extract(host)

        if not ext.domain:
            raise ValueError("Dominio no identificable")

        # dominio raíz limpio
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        else:
            return ext.domain

    except Exception as e:
        raise ValueError(f"No se pudo extraer dominio desde {url}: {e}")


# =========================
# HTTP ANALYSIS
# =========================
def analyze_http(url, timeout=10):
    """
    Análisis HTTP pasivo orientado a:
    - OSINT
    - Bug bounty
    - Forense web
    - Lectura de intención del backend
    """

    data = {
        "meta": {
            "reachable": False,
            "analyzed": False,
            "response_time_ms": None,
            "redirect_chain": [],
            "final_scheme": None,
            "final_host": None
        },
        "identity": {},
        "security_headers": {},
        "cache": {},
        "cookies": [],
        "signals": {},
        "heuristics": {}
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (ReconZen/1.0; Passive-Analysis)"
    })

    try:
        start = time.time()

        r = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True
        )

        elapsed = int((time.time() - start) * 1000)

        # =========================
        # META GENERAL
        # =========================
        parsed = urlparse(r.url)

        data["meta"].update({
            "reachable": True,
            "analyzed": True,
            "response_time_ms": elapsed,
            "redirect_chain": [h.url for h in r.history],
            "final_scheme": parsed.scheme,
            "final_host": parsed.netloc
        })

        data["status_code"] = r.status_code
        data["final_url"] = r.url
        data["method"] = r.request.method
        data["redirects"] = len(r.history)

        # =========================
        # IDENTIDAD TECNOLÓGICA
        # =========================
        headers = r.headers

        data["identity"] = {
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By"),
            "content_type": headers.get("Content-Type"),
            "content_length": headers.get("Content-Length"),
            "encoding": headers.get("Content-Encoding"),
            "date": headers.get("Date")
        }

        # =========================
        # HEADERS DE SEGURIDAD
        # =========================
        sec_headers = {
            "CSP": headers.get("Content-Security-Policy"),
            "HSTS": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
            "Cross-Origin-Opener-Policy": headers.get("Cross-Origin-Opener-Policy"),
            "Cross-Origin-Embedder-Policy": headers.get("Cross-Origin-Embedder-Policy")
        }

        data["security_headers"] = {k: bool(v) for k, v in sec_headers.items()}
        data["missing_security_headers"] = [
            k for k, v in data["security_headers"].items() if not v
        ]

        # =========================
        # CACHE & CONTROL
        # =========================
        cache_control = headers.get("Cache-Control", "")
        pragma = headers.get("Pragma")
        expires = headers.get("Expires")

        data["cache"] = {
            "cache_control": cache_control,
            "pragma": pragma,
            "expires": expires
        }

        data["signals"]["cache_loose"] = (
            "no-store" not in cache_control.lower()
            and "no-cache" not in cache_control.lower()
        )

        # =========================
        # COOKIES — LECTURA REAL
        # =========================
        weak_cookies = False

        for c in r.cookies:
            entry = {
                "name": c.name,
                "secure": c.secure,
                "httponly": c.has_nonstandard_attr("HttpOnly"),
                "samesite": c._rest.get("samesite")
            }
            data["cookies"].append(entry)

            if not entry["secure"] or not entry["httponly"]:
                weak_cookies = True

        data["signals"]["sets_cookies"] = bool(data["cookies"])
        data["signals"]["cookies_weak"] = weak_cookies

        # =========================
        # COMPORTAMIENTO HTTP
        # =========================
        ct = data["identity"]["content_type"] or ""

        data["signals"].update({
            "looks_like_api": "json" in ct.lower(),
            "binary_content": None,
            "exposes_stack": bool(
                data["identity"]["server"]
                or data["identity"]["powered_by"]
            ),
            "many_redirects": data["redirects"] > 2,
            "slow_response": elapsed > 2000,
            "forces_https": (
                parsed.scheme == "https"
                and any(h.url.startswith("http://") for h in r.history)
            )
        })

        # =========================
        # CONTENIDO PASIVO
        # =========================
        try:
            sample = r.raw.read(512, decode_content=True)
            data["signals"]["binary_content"] = b"\x00" in sample
        except Exception:
            data["signals"]["binary_content"] = None

        # =========================
        # HEURÍSTICAS DE INTENCIÓN
        # =========================
        data["heuristics"] = {
            "api_only_backend": (
                data["signals"]["looks_like_api"]
                and not data["cookies"]
            ),
            "tracking_heavy": (
                len(data["cookies"]) > 5
            ),
            "security_mature": (
                not data["missing_security_headers"]
                and not data["signals"]["cookies_weak"]
            ),
            "possible_waf_front": (
                "cloudflare" in (data["identity"]["server"] or "").lower()
                or "akamai" in (data["identity"]["server"] or "").lower()
            ),
            "redirect_obfuscation": (
                data["redirects"] >= 3
                and elapsed > 1500
            )
        }

    # =========================
    # ERRORES CONTROLADOS
    # =========================
    except requests.exceptions.Timeout:
        data["error"] = "HTTP timeout"
        data["signals"]["http_visibility"] = "timeout"

    except requests.exceptions.ConnectionError:
        data["error"] = "Connection error"
        data["signals"]["http_visibility"] = "blocked"

    except requests.exceptions.SSLError:
        data["error"] = "TLS negotiation failed"
        data["signals"]["http_visibility"] = "tls_error"

    except Exception as e:
        data["error"] = str(e)
        data["signals"]["http_visibility"] = "unknown"

    return data


@lru_cache(maxsize=256)
def analyze_dns(domain: str) -> dict:
    """
    Analiza DNS como señal OSINT avanzada.
    Diseñado para correlación de riesgo e intención operativa.
    """

    data = {
        "records": {},
        "meta": {},
        "signals": {},
        "heuristics": {},
        "confidence": {}
    }

    # =========================
    # RESOLVER DEFENSIVO
    # =========================
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6
    resolver.rotate = True

    query_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

    # =========================
    # RECOLECCIÓN TOLERANTE
    # =========================
    for rtype in query_types:
        try:
            answers = resolver.resolve(domain, rtype)
            data["records"][rtype] = [str(r).strip() for r in answers]
        except dns.resolver.NXDOMAIN:
            data["meta"]["nx_domain"] = True
            data["records"][rtype] = []
        except (dns.resolver.NoAnswer, dns.exception.Timeout):
            data["records"][rtype] = []
        except Exception:
            data["records"][rtype] = []

    # =========================
    # METADATA BASE
    # =========================
    A = data["records"].get("A", [])
    AAAA = data["records"].get("AAAA", [])
    MX = data["records"].get("MX", [])
    NS = data["records"].get("NS", [])
    TXT = data["records"].get("TXT", [])

    data["meta"] = {
        "has_ipv4": bool(A),
        "has_ipv6": bool(AAAA),
        "ip_count": len(A) + len(AAAA),
        "mx_count": len(MX),
        "ns_count": len(NS),
        "txt_count": len(TXT),
        "txt_size": sum(len(t) for t in TXT)
    }

    # =========================
    # NORMALIZACIÓN DE TEXTO
    # =========================
    mx_blob = " ".join(MX).lower()
    ns_blob = " ".join(NS).lower()
    txt_blob = " ".join(TXT).lower()

    # =========================
    # SEÑALES CLÁSICAS (INVERSAS)
    # =========================
    data["signals"].update({
        "generic_mx": any(p in mx_blob for p in [
            "google", "outlook", "hotmail",
            "yahoodns", "zoho", "icloud"
        ]),
        "low_ns_redundancy": data["meta"]["ns_count"] < 2,
        "txt_overloaded": data["meta"]["txt_size"] > 512,
        "looks_cloud_managed": any(p in ns_blob for p in [
            "cloudflare", "aws", "amazon",
            "azure", "gcp", "google",
            "digitalocean", "linode"
        ])
    })

    # =========================
    # HEURÍSTICAS DE INTENCIÓN
    # =========================

    # Infra mínima → API / backend / landing desechable
    data["heuristics"]["infra_minimalist"] = (
        data["meta"]["ip_count"] <= 1
        and data["meta"]["mx_count"] <= 1
        and data["meta"]["txt_count"] <= 2
    )

    # TXT ruidoso → exceso de automatización / deuda
    data["heuristics"]["automation_heavy"] = (
        "spf" in txt_blob
        and ("dkim" in txt_blob or "dmarc" in txt_blob)
        and data["meta"]["txt_count"] > 3
    )

    # Web sin correo → decisión consciente
    data["heuristics"]["email_disabled"] = (
        data["meta"]["mx_count"] == 0
        and data["meta"]["ip_count"] > 0
    )

    # NS de proveedores distintos → migración o takeover previo
    providers = {
        ".".join(n.split(".")[-2:]) for n in NS if "." in n
    }
    data["heuristics"]["ns_heterogeneous"] = len(providers) > 1

    # IPv6-only → infra moderna / experimental
    data["heuristics"]["ipv6_only"] = (
        data["meta"]["has_ipv6"] and not data["meta"]["has_ipv4"]
    )

    # =========================
    # MADUREZ OPERATIVA
    # =========================
    if data["signals"]["looks_cloud_managed"] and not data["signals"]["low_ns_redundancy"]:
        maturity = "alta"
    elif data["meta"]["ns_count"] >= 2:
        maturity = "media"
    else:
        maturity = "baja"

    data["signals"]["infra_maturity"] = maturity

    # =========================
    # SILENCIO COMO SEÑAL
    # =========================
    data["signals"]["sparse_dns"] = (
        data["meta"]["ip_count"] == 0
        and data["meta"]["mx_count"] == 0
    )

    # =========================
    # CONFIANZA DEL ANÁLISIS
    # =========================
    data["confidence"] = {
        "dns_responsive": not data["meta"].get("nx_domain", False),
        "analysis_reliable": data["meta"]["ns_count"] > 0
    }

    return data


# =========================
# TLS PROFUNDO
# =========================

def analyze_tls(domain, ports=(443, 8443), timeout=5):
    """
    Observación TLS pasiva y robusta.
    Diseñada para lectura inversa, OSINT y criterio técnico.
    """
    info = {
        "certificate": {},
        "crypto": {},
        "validity": {},
        "signals": {},
        "meta": {
            "tested_ports": [],
            "ip_versions": [],
            "handshake": False,
            "attempts": 0
        }
    }

    def _init_error(reason):
        info["error"] = reason
        info["signals"].update({
            "tls_visibility": "none",
            "interpretable": False
        })
        return info

    # =========================
    # RESOLUCIÓN IP (V4 / V6)
    # =========================
    addresses = []
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                res = socket.getaddrinfo(domain, None, fam, socket.SOCK_STREAM)
                for r in res:
                    addresses.append((fam, r[4][0]))
            except Exception:
                continue
    except Exception:
        return _init_error("DNS resolution failed")

    if not addresses:
        return _init_error("No IP addresses resolved")

    # =========================
    # CONTEXTO TLS (ANTI-ARTEFACTOS)
    # =========================
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_NO_TICKET  # reduce fingerprint noise

    # =========================
    # MULTI-IP / MULTI-PUERTO
    # =========================
    for fam, ip in addresses:
        ip_ver = "IPv6" if fam == socket.AF_INET6 else "IPv4"
        if ip_ver not in info["meta"]["ip_versions"]:
            info["meta"]["ip_versions"].append(ip_ver)

        for port in ports:
            info["meta"]["tested_ports"].append(port)
            info["meta"]["attempts"] += 1

            try:
                raw = socket.socket(fam, socket.SOCK_STREAM)
                raw.settimeout(timeout)

                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    s.connect((ip, port))
                    info["meta"]["handshake"] = True

                    cert_bin = s.getpeercert(binary_form=True)
                    if not cert_bin:
                        raise ssl.SSLError("No certificate presented")

                    pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                    x509 = ssl._ssl._test_decode_cert(pem)

                    # =========================
                    # CERTIFICADO
                    # =========================
                    issuer = x509.get("issuer")
                    subject = x509.get("subject")
                    sans = x509.get("subjectAltName", [])

                    info["certificate"] = {
                        "issuer": issuer,
                        "subject": subject,
                        "SANs": sans,
                        "self_signed": issuer == subject,
                        "san_count": len(sans)
                    }

                    # =========================
                    # VALIDEZ TEMPORAL
                    # =========================
                    fmt = "%b %d %H:%M:%S %Y %Z"
                    nb = x509.get("notBefore")
                    na = x509.get("notAfter")

                    if nb and na:
                        start = datetime.strptime(nb, fmt)
                        end = datetime.strptime(na, fmt)
                        days = (end - datetime.utcnow()).days

                        info["validity"] = {
                            "valid_from": nb,
                            "valid_to": na,
                            "days_remaining": days
                        }

                        info["signals"]["near_expiration"] = days < 30
                        info["signals"]["expired"] = days < 0
                    else:
                        info["signals"]["near_expiration"] = None

                    # =========================
                    # CRIPTOGRAFÍA ACTIVA
                    # =========================
                    cipher = s.cipher() or ("unknown", "", 0)
                    tls_version = s.version()

                    info["crypto"] = {
                        "tls_version": tls_version,
                        "cipher_suite": cipher[0],
                        "key_length": cipher[2],
                        "signature_algorithm": x509.get("signatureAlgorithm")
                    }

                    # =========================
                    # SEÑALES INVERSAS (LECTURA)
                    # =========================
                    info["signals"].update({
                        "weak_key": cipher[2] < 2048 if cipher[2] else None,
                        "legacy_tls": tls_version in ("TLSv1", "TLSv1.1"),
                        "shared_certificate": len(sans) > 5,
                        "wildcard_cert": any("*." in s[1] for s in sans if isinstance(s, tuple)),
                        "lets_encrypt": "let's encrypt" in str(issuer).lower(),
                        "tls_visibility": "full",
                        "interpretable": True
                    })

                    # =========================
                    # META LECTURA (NO TÉCNICA)
                    # =========================
                    info["signals"]["infra_hint"] = (
                        "mass_hosting" if len(sans) > 10 else
                        "managed" if "let's encrypt" in str(issuer).lower() else
                        "custom"
                    )

                    return info  # salida limpia y estable

            except ssl.SSLError as e:
                info["signals"]["tls_visibility"] = "blocked"
                info["error"] = f"SSL error on {ip}:{port} → {e}"

            except socket.timeout:
                info["signals"]["tls_visibility"] = "timeout"
                info["error"] = f"Timeout on {ip}:{port}"

            except ConnectionRefusedError:
                info["signals"]["tls_visibility"] = "refused"
                info["error"] = f"Connection refused on {ip}:{port}"

            except Exception as e:
                info["signals"]["tls_visibility"] = "unknown"
                info["error"] = str(e)

    # =========================
    # POST-MORTEM SIN HANDSHAKE
    # =========================
    if not info["meta"]["handshake"]:
        info["signals"].update({
            "tls_visibility": "absent",
            "interpretable": False
        })

    return info


@lru_cache(maxsize=256)
def analyze_whois(domain: str) -> dict:
    """
    Analiza WHOIS como señal OSINT avanzada.
    No confía ciegamente en el parser.
    Diseñado para correlación de riesgo, no para mostrar datos bonitos.
    """

    info = {
        "identity": {},
        "dates": {},
        "meta": {},
        "signals": {},
        "raw": {},
        "confidence": {}
    }

    # =========================
    # NORMALIZADOR TEMPORAL
    # =========================
    def normalize_date(d):
        if isinstance(d, list) and d:
            d = d[0]
        return d if isinstance(d, datetime) else None

    def days_between(a, b):
        return (b - a).days if isinstance(a, datetime) and isinstance(b, datetime) else None

    try:
        w = whois.whois(domain)

        # =========================
        # RAW (DESCONFIANZA CONTROLADA)
        # =========================
        info["raw"]["available"] = bool(w)
        info["raw"]["text_hint"] = str(w)[:800] if w else None

        # =========================
        # IDENTIDAD (TOLERANTE A VACÍOS)
        # =========================
        info["identity"] = {
            "registrar": getattr(w, "registrar", None),
            "country": getattr(w, "country", None),
            "org": getattr(w, "org", None),
            "name": getattr(w, "name", None),
            "emails": []
        }

        emails = getattr(w, "emails", None)
        if isinstance(emails, str):
            emails = [emails]
        if isinstance(emails, list):
            info["identity"]["emails"] = emails

        # =========================
        # FECHAS (NORMALIZADAS)
        # =========================
        creation = normalize_date(getattr(w, "creation_date", None))
        expiration = normalize_date(getattr(w, "expiration_date", None))
        updated = normalize_date(getattr(w, "updated_date", None))

        info["dates"] = {
            "creation_date": creation,
            "expiration_date": expiration,
            "updated_date": updated
        }

        # =========================
        # METADATA TEMPORAL
        # =========================
        now = datetime.utcnow()

        info["meta"] = {
            "domain_age_days": days_between(creation, now),
            "days_to_expire": days_between(now, expiration),
            "days_since_update": days_between(updated, now)
        }

        # =========================
        # SEÑALES TEMPORALES (INTENCIÓN)
        # =========================
        info["signals"].update({
            "young_domain": info["meta"]["domain_age_days"] is not None and info["meta"]["domain_age_days"] < 180,
            "very_young_domain": info["meta"]["domain_age_days"] is not None and info["meta"]["domain_age_days"] < 30,
            "long_lived_domain": info["meta"]["domain_age_days"] is not None and info["meta"]["domain_age_days"] > 3650,
            "expiring_soon": info["meta"]["days_to_expire"] is not None and info["meta"]["days_to_expire"] < 60,
            "recently_modified": info["meta"]["days_since_update"] is not None and info["meta"]["days_since_update"] < 30,
        })

        # =========================
        # PRIVACIDAD / OPACIDAD
        # =========================
        privacy_tokens = [
            "privacy", "redacted", "whoisguard",
            "proxy", "contact privacy", "gdpr"
        ]

        blob = " ".join([
            str(info["identity"].get("registrar")),
            str(info["identity"].get("org")),
            info["raw"].get("text_hint", "")
        ]).lower()

        info["signals"]["privacy_protected"] = any(t in blob for t in privacy_tokens)

        # =========================
        # REPUTACIÓN DEL REGISTRAR
        # =========================
        high_rep_registrars = [
            "markmonitor", "csc", "gandi",
            "cloudflare", "aws", "google"
        ]

        registrar = (info["identity"]["registrar"] or "").lower()

        info["signals"]["registrar_reputation_hint"] = (
            "alta" if any(r in registrar for r in high_rep_registrars)
            else "media" if registrar else "desconocida"
        )

        # =========================
        # COHERENCIA TEMPORAL (ANTI-FRAUDE)
        # =========================
        info["signals"]["temporal_inconsistency"] = (
            creation and updated and updated < creation
        )

        # =========================
        # CALIDAD DE WHOIS
        # =========================
        info["signals"]["sparse_whois"] = (
            not info["identity"]["registrar"]
            or not info["dates"]["creation_date"]
        )

        # =========================
        # CONFIANZA DEL PARSER
        # =========================
        info["confidence"] = {
            "whois_reliable": not info["signals"]["sparse_whois"]
                               and not info["signals"]["temporal_inconsistency"],
            "human_readable": bool(info["raw"]["text_hint"]),
        }

    except Exception as e:
        return {
            "error": str(e),
            "signals": {
                "whois_unavailable": True
            },
            "confidence": {
                "whois_reliable": False
            }
        }

    return info


# =========================
# TRUST SCORE (CRITERIO REAL)
# =========================

def trust_score(http, tls, whois_data, dns):
    """
    Trust Score pasivo.
    Evalúa higiene, madurez e intención técnica.
    """
    score = 100
    notes = []

    # =========================
    # NORMALIZADORES (ANTI-CAOS)
    # =========================
    security_headers = http.get("security_headers") or {}
    dns_records = dns.get("records") or dns if isinstance(dns, dict) else {}
    dns_signals = dns.get("signals") or {}
    tls_crypto = tls.get("crypto") or tls if isinstance(tls, dict) else {}
    tls_signals = tls.get("signals") or {}

    # =========================
    # HEADERS · HIGIENE WEB
    # =========================
    missing_headers = [
        h for h, present in security_headers.items() if not present
    ]

    penalty = min(len(missing_headers) * 6, 24)
    score -= penalty

    for h in missing_headers:
        notes.append(f"Header de seguridad ausente: {h}")

    # =========================
    # EDAD DEL DOMINIO · INTENCIÓN
    # =========================
    creation_date = (
        whois_data.get("creation_date")
        or whois_data.get("dates", {}).get("creation_date")
    )

    if isinstance(creation_date, datetime):
        age_days = (datetime.utcnow() - creation_date).days

        if age_days < 90:
            score -= 25
            notes.append("Dominio extremadamente reciente")
        elif age_days < 180:
            score -= 15
            notes.append("Dominio joven")
        elif age_days > 3650:
            score += 5
            notes.append("Dominio longevo (señal positiva)")

    # =========================
    # TLS · CRIPTOGRAFÍA
    # =========================
    key_length = tls_crypto.get("key_length")
    if isinstance(key_length, int):
        if key_length < 2048:
            score -= 20
            notes.append("Clave TLS insuficiente (<2048 bits)")
        elif key_length >= 4096:
            score += 5
            notes.append("Clave TLS robusta (≥4096 bits)")

    if tls_signals.get("legacy_tls"):
        score -= 15
        notes.append("Uso de TLS legado")

    if tls_signals.get("near_expiration"):
        score -= 10
        notes.append("Certificado TLS próximo a expirar")

    # =========================
    # DNS · RESILIENCIA INFRA
    # =========================
    mx_records = dns_records.get("MX") or []
    ns_records = dns_records.get("NS") or []
    txt_records = dns_records.get("TXT") or []

    if any("google" in mx.lower() for mx in mx_records if isinstance(mx, str)):
        score -= 5
        notes.append("MX genérico (infraestructura commodity)")

    if len(ns_records) < 2:
        score -= 10
        notes.append("Falta de redundancia en NS")

    txt_volume = sum(len(t) for t in txt_records if isinstance(t, str))
    if txt_volume > 512:
        score -= 5
        notes.append("Registros TXT extensos / desordenados")

    if dns_signals.get("looks_cloud_managed"):
        score += 5
        notes.append("Infraestructura gestionada (cloud-managed)")

    # =========================
    # NORMALIZACIÓN FINAL
    # =========================
    score = max(0, min(score, 100))

    if score >= 80:
        notes.append("Perfil técnico consistente y maduro")
    elif score < 40:
        notes.append("Perfil de riesgo elevado")

    return score, notes



# =========================
# VISUALIZACION
# =========================

def show_table(title, data_dict):
    table = Table(
        title=title,
        show_lines=True,
        expand=True,
        header_style="bold bright_magenta"
    )

    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="green")

    def render_value(value, level=0):
        indent = "  " * level

        # --- Diccionarios ---
        if isinstance(value, dict):
            if not value:
                return f"{indent}—"
            lines = []
            for k, v in value.items():
                rendered = render_value(v, level + 1)
                lines.append(f"{indent}🔹 {k}: {rendered}")
            return "\n".join(lines)

        # --- Listas ---
        if isinstance(value, list):
            if not value:
                return f"{indent}—"
            return "\n".join(
                f"{indent}• {render_value(item, level + 1)}"
                for item in value
            )

        # --- Booleanos ---
        if isinstance(value, bool):
            return f"{indent}{'✅ True' if value else '❌ False'}"

        # --- Nulos ---
        if value is None:
            return f"{indent}—"

        # --- Texto / valores simples ---
        text = str(value).strip()
        if not text:
            return f"{indent}—"

        if len(text) > 120:
            text = text[:117] + "…"

        return f"{indent}{text}"

    # =========================
    # RENDER DE TABLA
    # =========================
    if not data_dict or not isinstance(data_dict, dict):
        table.add_row("—", "Sin datos disponibles")
    else:
        for key in sorted(data_dict.keys(), key=lambda x: str(x)):
            table.add_row(str(key), render_value(data_dict.get(key)))

    console.print(table)


import hashlib


def analyze_tls_fingerprint(tls):
    """
    Fingerprint TLS server-side
    JA3S / JA4-S (aproximación pasiva + lectura inversa forense)
    """

    result = {
        "fingerprints": {},
        "profile": {},
        "signals": {},
        "insights": [],
        "meta": {}
    }

    # =========================
    # VALIDACIÓN ANTI-FRÁGIL
    # =========================
    if not isinstance(tls, dict):
        return {"error": "TLS structure inválida"}

    crypto = tls.get("crypto") or tls
    if not isinstance(crypto, dict):
        return {"error": "TLS crypto no disponible"}

    # =========================
    # EXTRACCIÓN DEFENSIVA
    # =========================
    proto = str(
        crypto.get("tls_version")
        or crypto.get("protocol")
        or "unknown"
    ).strip()

    cipher = str(
        crypto.get("cipher_suite")
        or crypto.get("cipher")
        or "unknown"
    ).strip()

    bits = crypto.get("key_length") or crypto.get("bits") or 0
    try:
        bits = int(bits)
    except Exception:
        bits = 0

    # Normalización fuerte (anti-ruido)
    proto_n = proto.upper()
    cipher_n = cipher.upper()

    # =========================
    # JA3S — SERVER HELLO
    # =========================
    ja3s_raw = f"{proto_n},{cipher_n},{bits}"
    ja3s_hash = hashlib.md5(
        ja3s_raw.encode("utf-8", errors="ignore")
    ).hexdigest()

    # =========================
    # JA4-S — PERFIL SERVIDOR
    # (aprox estable, no canónico)
    # =========================
    ja4s_raw = f"{proto_n}|{cipher_n}"
    ja4s_hash = hashlib.sha256(
        ja4s_raw.encode("utf-8", errors="ignore")
    ).hexdigest()[:16]

    result["fingerprints"] = {
        "ja3s_raw": ja3s_raw,
        "ja3s_hash": ja3s_hash,
        "ja4s_raw": ja4s_raw,
        "ja4s_hash": ja4s_hash
    }

    # =========================
    # PERFIL CRIPTOGRÁFICO
    # =========================
    result["profile"] = {
        "protocol": proto_n,
        "cipher": cipher_n,
        "key_bits": bits
    }

    # =========================
    # SEÑALES TÉCNICAS
    # =========================
    result["signals"] = {
        "modern_tls": proto_n.startswith("TLSV1.3"),
        "legacy_tls": proto_n in ("TLSV1", "TLSV1.1"),
        "forward_secrecy": "ECDHE" in cipher_n,
        "mobile_optimized": "CHACHA20" in cipher_n,
        "weak_crypto": bits != 0 and bits < 128,
        "standard_cipher": any(x in cipher_n for x in ["AES", "CHACHA"]),
    }

    # =========================
    # LECTURA INVERSA (FORENSE)
    # =========================
    if result["signals"]["modern_tls"]:
        result["insights"].append(
            "TLS moderno → stack actualizado o CDN/WAF delante"
        )
    elif proto_n.startswith("TLSV1.2"):
        result["insights"].append(
            "TLS 1.2 → compatibilidad amplia, posible legacy controlado"
        )
    else:
        result["insights"].append(
            "Protocolo atípico → posible downgrade, IoT o stack obsoleto"
        )

    if result["signals"]["forward_secrecy"]:
        result["insights"].append(
            "Forward Secrecy presente → buen hygiene criptográfico"
        )

    if result["signals"]["mobile_optimized"]:
        result["insights"].append(
            "Cifrado CHACHA → optimización móvil / edge"
        )

    if result["signals"]["weak_crypto"]:
        result["insights"].append(
            "Entropía débil → riesgo de downgrade o mala configuración"
        )

    if "RSA" in cipher_n and "ECDHE" not in cipher_n:
        result["insights"].append(
            "Handshake RSA puro → patrón legacy / compat extrema"
        )

    # =========================
    # META-LECTURA (NIVEL DIOS)
    # =========================
    result["meta"] = {
        "fingerprint_stability": "alta" if proto_n != "unknown" and cipher_n != "unknown" else "media",
        "correlation_ready": True,
        "intended_use": [
            "CDN vs Origin detection",
            "ASN correlation",
            "CVE historical mapping",
            "Threat profiling",
            "Bug bounty reconnaissance"
        ]
    }

    if not result["insights"]:
        result["insights"].append("Perfil TLS neutro")

    result["note"] = (
        "Fingerprint TLS server-side pasivo "
        "(JA3S / JA4-S approx · lectura inversa · anti-frágil)"
    )

    return result


def detect_cdn_vs_origin(domain, dns, tls):
    """
    Detección heurística CDN vs ORIGIN
    Enfoque OSINT / RedTeam defensivo (100% pasivo)
    Lectura inversa de infraestructura expuesta vs abstraída
    """

    result = {
        "domain": domain,
        "verdict": "ORIGIN",
        "confidence": "LOW",
        "score": 0,
        "signals": [],
        "insights": [],
        "meta": {}
    }

    # =========================
    # NORMALIZACIÓN ANTI-FRÁGIL
    # =========================
    dns = dns if isinstance(dns, dict) else {}
    tls = tls if isinstance(tls, dict) else {}

    records = dns.get("records", {})
    meta = dns.get("meta", {})

    # =========================
    # BASE DE CONOCIMIENTO CDN
    # =========================
    cdn_keywords = [
        "cloudflare", "akamai", "fastly", "cloudfront",
        "edgesuite", "cdn", "imperva", "incapsula",
        "stackpath", "sucuri", "azureedge", "google"
    ]

    # =========================
    # 1️⃣ DNS — CNAME / NS
    # =========================
    cnames = records.get("CNAME", []) or []
    ns = records.get("NS", []) or []

    for r in cnames + ns:
        r_low = r.lower()
        for kw in cdn_keywords:
            if kw in r_low:
                result["signals"].append(
                    f"DNS apunta a proveedor CDN ({kw})"
                )
                result["score"] += 2

    # =========================
    # 2️⃣ DISTRIBUCIÓN IP
    # =========================
    a_records = records.get("A", []) or []
    aaaa_records = records.get("AAAA", []) or []

    ip_count = len(a_records) + len(aaaa_records)

    if ip_count >= 4:
        result["signals"].append(
            "Alta dispersión IP (patrón edge / anycast)"
        )
        result["score"] += 1
    elif ip_count == 1:
        result["signals"].append(
            "IP única (posible origin directo)"
        )

    # =========================
    # 3️⃣ TTL — DINÁMICA DE CACHÉ
    # =========================
    ttl = meta.get("ttl")

    if isinstance(ttl, int):
        if ttl < 300:
            result["signals"].append(
                "TTL bajo (rotación agresiva / edge caching)"
            )
            result["score"] += 1
        elif ttl > 3600:
            result["signals"].append(
                "TTL alto (infra estable / posible origin)"
            )

    # =========================
    # 4️⃣ TLS — ISSUER / CERTIFICADO
    # =========================
    issuer = tls.get("certificate", {}).get("issuer", {})
    issuer_blob = " ".join(str(v) for v in issuer.values()).lower()

    for kw in cdn_keywords:
        if kw in issuer_blob:
            result["signals"].append(
                f"Certificado TLS gestionado por CDN ({kw})"
            )
            result["score"] += 2

    # =========================
    # 5️⃣ TLS — PERFIL CRIPTOGRÁFICO
    # =========================
    crypto = tls.get("crypto", {})
    proto = str(
        crypto.get("tls_version")
        or crypto.get("protocol")
        or ""
    ).lower()

    cipher = str(
        crypto.get("cipher_suite")
        or crypto.get("cipher")
        or ""
    ).lower()

    if "tlsv1.3" in proto and any(x in cipher for x in ["aes", "chacha"]):
        result["signals"].append(
            "Perfil TLS estandarizado (plantilla edge/CDN)"
        )
        result["score"] += 1

    # =========================
    # 6️⃣ SEÑALES NEGATIVAS (ANTI-FALSO POSITIVO)
    # =========================
    if ip_count <= 1 and not result["signals"]:
        result["signals"].append(
            "Ausencia de abstracción infra (sin capa intermedia clara)"
        )

    # =========================
    # VEREDICTO FINAL
    # =========================
    if result["score"] >= 5:
        result["verdict"] = "CDN"
        result["confidence"] = "HIGH"
    elif result["score"] >= 3:
        result["verdict"] = "CDN"
        result["confidence"] = "MEDIUM"
    else:
        result["verdict"] = "ORIGIN"
        result["confidence"] = "LOW"

    # =========================
    # LECTURA INVERSA (HUMANA)
    # =========================
    if result["verdict"] == "CDN":
        result["insights"].extend([
            "El origin real está oculto tras infraestructura intermedia",
            "La superficie observable es una abstracción defensiva",
            "Ataques directos al backend requieren ruptura de capa CDN"
        ])
    else:
        result["insights"].extend([
            "Infraestructura expuesta directamente a Internet",
            "Menor separación entre servicio, red y host",
            "Mayor relevancia de hardening a nivel servidor"
        ])

    # =========================
    # META — LISTO PARA CORRELACIÓN
    # =========================
    result["meta"] = {
        "correlation_ready": True,
        "intended_use": [
            "Origin discovery",
            "Infra exposure scoring",
            "Bug bounty recon",
            "Red/Blue team profiling"
        ]
    }

    if not result["signals"]:
        result["signals"].append("Sin indicadores fuertes de CDN")

    return result


def analyze_asn(domain):
    """
    Análisis ASN pasivo (infraestructura real detrás del dominio)
    Enfoque OSINT · lectura inversa · correlación CDN ↔ proveedor ↔ masking
    No intrusivo · tolerante a fallos · orientado a señales
    """

    result = {
        "ips": [],
        "asn": [],
        "org": [],
        "country": [],
        "notes": []
    }

    # =========================
    # VALIDACIÓN BASE
    # =========================
    if not isinstance(domain, str) or not domain.strip():
        return {
            "error": "Dominio inválido",
            "notes": ["Entrada no válida para análisis ASN"]
        }

    domain = domain.strip()

    # =========================
    # 1️⃣ RESOLUCIÓN IP (PASIVA)
    # =========================
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({i[4][0] for i in infos if i and i[4]})
        if not ips:
            result["notes"].append("Resolución DNS vacía")
            return result
        result["ips"] = ips
    except Exception:
        result["notes"].append("No se pudieron resolver IPs")
        return result

    # =========================
    # 2️⃣ WHOIS ASN (LECTURA SUAVE)
    # =========================
    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
            whois_data = whois.whois(str(obj)) or {}

            asn = whois_data.get("asn")
            org = (
                whois_data.get("org")
                or whois_data.get("organization")
                or whois_data.get("descr")
            )
            country = whois_data.get("country")

            if asn:
                result["asn"].append(str(asn))
            if org:
                result["org"].append(str(org).strip())
            if country:
                result["country"].append(str(country).strip())

        except Exception:
            # Silencio forense: una IP fallida no rompe la lectura
            continue

    # =========================
    # 3️⃣ NORMALIZACIÓN LIMPIA
    # =========================
    for key in ("asn", "org", "country"):
        result[key] = sorted(set(result[key]))

    # =========================
    # 4️⃣ LECTURA INVERSA (SIGNIFICADO)
    # =========================
    if not result["asn"]:
        result["notes"].append(
            "ASN no visible directamente (probable CDN, proxy o edge masking)"
        )

    if len(result["org"]) > 1:
        result["notes"].append(
            "Múltiples organizaciones detectadas (infraestructura distribuida)"
        )

    if result["asn"]:
        result["notes"].append(
            "Proveedor de red parcialmente observable"
        )

    if len(result["ips"]) > 3:
        result["notes"].append(
            "Múltiples IPs asociadas (posible balanceo o edge network)"
        )

    if not result["notes"]:
        result["notes"].append(
            "Infraestructura ASN neutra sin señales fuertes"
        )

    return result



def generate_enterprise_criteria(http, dns, tls, whois_data, score):
    criteria = {
        "posture": "desconocida",
        "maturity": "baja",
        "defensive": [],
        "offensive_surface": [],
        "strategic_notes": []
    }

    # =========================
    # POSTURA GENERAL
    # =========================
    if score >= 80:
        criteria["posture"] = "robusta"
        criteria["maturity"] = "alta"
    elif score >= 40:
        criteria["posture"] = "intermedia"
        criteria["maturity"] = "media"
    else:
        criteria["posture"] = "frágil"
        criteria["maturity"] = "baja"

    # =========================
    # LECTURA DEFENSIVA
    # =========================
    if dns.get("signals", {}).get("low_ns_redundancy"):
        criteria["defensive"].append(
            "Incrementar redundancia DNS para resiliencia operativa."
        )

    if dns.get("signals", {}).get("txt_overloaded"):
        criteria["defensive"].append(
            "Reducir y segmentar registros TXT (SPF / DKIM / DMARC) para evitar ruido y errores."
        )

    if not tls or tls.get("meta", {}).get("grade") in ["C", "D", "F"]:
        criteria["defensive"].append(
            "Reforzar configuración TLS (ciphers modernos, forward secrecy, HSTS)."
        )

    if http.get("signals", {}).get("tech_exposed"):
        criteria["defensive"].append(
            "Minimizar exposición tecnológica en headers HTTP."
        )

    if whois_data.get("signals", {}).get("privacy_protected") is False:
        criteria["defensive"].append(
            "Habilitar privacidad WHOIS para reducir huella organizacional."
        )

    # =========================
    # LECTURA OFENSIVA (ABSTRACTA)
    # =========================
    if criteria["maturity"] == "baja":
        criteria["offensive_surface"].append(
            "Infraestructura sugiere improvisación o crecimiento no planificado."
        )

    if dns.get("signals", {}).get("generic_mx"):
        criteria["offensive_surface"].append(
            "Dependencia de proveedores genéricos revela centralización operativa."
        )

    if http.get("meta", {}).get("redirect_chain", 0) > 2:
        criteria["offensive_surface"].append(
            "Cadena de redirecciones indica posible complejidad mal gestionada."
        )

    if tls.get("signals", {}).get("expired_cert"):
        criteria["offensive_surface"].append(
            "Gestión criptográfica reactiva en lugar de preventiva."
        )

    # =========================
    # NOTAS ESTRATÉGICAS
    # =========================
    criteria["strategic_notes"].extend([
        "La seguridad percibida comunica cultura interna.",
        "Infraestructura limpia reduce superficie cognitiva del adversario.",
        "El orden técnico suele reflejar orden organizacional.",
        "La ausencia de señales también es una señal."
    ])

    return criteria


def correlate_cdn_ja3_asn(domain, dns, tls, tls_fp, asn_info=None):
    """
    Correlación avanzada:
    CDN ↔ JA3S ↔ ASN ↔ Proveedor real
    Enfoque: lectura inversa ofensiva / criterio defensivo
    """

    result = {
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "correlations": [],
        "offensive_insights": [],
        "defensive_insights": [],
        "strategic_reading": []
    }

    score = 0

    # =========================
    # NORMALIZACIÓN
    # =========================
    dns = dns or {}
    tls = tls or {}
    tls_fp = tls_fp or {}
    asn_info = asn_info or {}

    # =========================
    # 1️⃣ CDN DETECTADO
    # =========================
    cdn_hint = False
    cdn_names = ["cloudflare", "akamai", "fastly", "cloudfront", "imperva"]

    ns_records = dns.get("records", {}).get("NS", [])
    for ns in ns_records:
        for cdn in cdn_names:
            if cdn in ns.lower():
                cdn_hint = True
                score += 2
                result["correlations"].append(f"NS revela CDN ({cdn})")

    # =========================
    # 2️⃣ JA3S / JA4-S PATTERN
    # =========================
    ja3s = tls_fp.get("ja3s_hash", "")
    if ja3s:
        score += 1
        result["correlations"].append("Fingerprint TLS estable (JA3S presente)")

        if cdn_hint:
            result["correlations"].append(
                "JA3S consistente con plantillas TLS de edge/CDN"
            )

    # =========================
    # 3️⃣ CERT ISSUER ↔ CDN
    # =========================
    issuer = tls.get("certificate", {}).get("issuer", {})
    issuer_blob = " ".join(str(v) for v in issuer.values()).lower()

    for cdn in cdn_names:
        if cdn in issuer_blob:
            score += 2
            result["correlations"].append(
                f"Certificado gestionado por proveedor CDN ({cdn})"
            )

    # =========================
    # 4️⃣ ASN / PROVIDER REAL
    # =========================
    asn_name = str(asn_info.get("asn_name", "")).lower()
    asn_org = str(asn_info.get("org", "")).lower()

    for cdn in cdn_names:
        if cdn in asn_name or cdn in asn_org:
            score += 2
            result["correlations"].append(
                f"ASN pertenece a infraestructura CDN ({cdn})"
            )

    if asn_info and not cdn_hint:
        result["correlations"].append(
            "ASN apunta a proveedor directo (posible origin real)"
        )

    # =========================
    # 🎯 VEREDICTO
    # =========================
    if score >= 6:
        result["verdict"] = "CDN_SHIELDED_ORIGIN"
        result["confidence"] = "HIGH"
    elif score >= 3:
        result["verdict"] = "CDN_LIKELY"
        result["confidence"] = "MEDIUM"
    else:
        result["verdict"] = "DIRECT_ORIGIN"
        result["confidence"] = "LOW"

    # =========================
    # 👁️ LECTURA OFENSIVA (NO INTRUSIVA)
    # =========================
    if result["verdict"] != "DIRECT_ORIGIN":
        result["offensive_insights"] = [
            "La IP visible no corresponde al origin real",
            "El fingerprint TLS es genérico y compartido",
            "Cualquier escaneo directo golpeará el edge, no el core",
            "El verdadero backend vive detrás del perímetro lógico"
        ]
    else:
        result["offensive_insights"] = [
            "Infraestructura responde directamente",
            "Menor separación entre red y aplicación",
            "TLS fingerprint es específico del host",
            "ASN expone proveedor real"
        ]

    # =========================
    # 🛡️ LECTURA DEFENSIVA
    # =========================
    if result["verdict"].startswith("CDN"):
        result["defensive_insights"] = [
            "Arquitectura correctamente segmentada",
            "Buen aislamiento entre edge y origin",
            "Menor riesgo de exposición directa"
        ]
    else:
        result["defensive_insights"] = [
            "Falta capa de abstracción (CDN / WAF)",
            "Origin expuesto a fingerprinting directo",
            "Mayor superficie de observación externa"
        ]

    # =========================
    # 🧠 LECTURA ESTRATÉGICA
    # =========================
    result["strategic_reading"] = [
        "El fingerprint no revela vulnerabilidad, revela madurez",
        "Lo invisible suele ser más importante que lo visible",
        "Una infraestructura silenciosa comunica control",
        "La defensa moderna es abstracción, no ocultamiento"
    ]

    return result


def analyze_offensive_surface(http, dns, tls, cdn_info, asn_info):
    """
    Análisis abstracto de superficie ofensiva.
    Pensado para bug bounty / threat modeling.
    Lectura pasiva, sin explotación.
    """
    surface = []
    weight = 0

    # =========================
    # HTTP / APLICACIÓN
    # =========================
    headers = http.get("headers", {}) if isinstance(http, dict) else {}

    if not headers.get("Content-Security-Policy"):
        surface.append("Ausencia de CSP → superficie XSS / injection")
        weight += 2

    if not headers.get("X-Frame-Options"):
        surface.append("Falta X-Frame-Options → riesgo clickjacking")
        weight += 1

    if http.get("redirects", 0) > 2:
        surface.append("Cadena de redirecciones → posible open redirect / confusion")
        weight += 1

    if headers.get("Server"):
        surface.append("Header Server expuesto → fingerprinting de stack")
        weight += 1

    # =========================
    # DNS / CORREO / METADATA
    # =========================
    if dns.get("MX"):
        surface.append("MX expuesto → vector phishing / spoofing")
        weight += 2

    if dns.get("TXT"):
        surface.append("TXT visibles → fuga de metadatos (SPF, verificación)")
        weight += 1

    if dns.get("CNAME") and len(dns.get("CNAME")) > 1:
        surface.append("Múltiples CNAME → complejidad infra / errores de routing")
        weight += 1

    # =========================
    # TLS / CRIPTOGRAFÍA
    # =========================
    proto = tls.get("protocol")
    cipher = tls.get("cipher", "")

    if proto in ["TLSv1", "TLSv1.1"]:
        surface.append("TLS legacy → downgrade / compat flaws")
        weight += 3

    if "CBC" in cipher or "SHA1" in cipher:
        surface.append("Cipher débil detectado → riesgo criptográfico histórico")
        weight += 2

    # =========================
    # CDN vs ORIGIN
    # =========================
    if cdn_info.get("verdict") == "ORIGIN":
        surface.append("Origen directo expuesto → ataque directo a infraestructura")
        weight += 3
    elif cdn_info.get("verdict") == "CDN":
        surface.append("CDN presente → superficie directa parcialmente mitigada")
        weight -= 1

    # =========================
    # ASN / CONTEXTO INFRA
    # =========================
    if asn_info.get("type") == "hosting":
        surface.append("Infra en hosting público → menor control perimetral")
        weight += 2

    if asn_info.get("cloud") is True:
        surface.append("Infra cloud compartida → ruido multi-tenant")
        weight += 1

    # =========================
    # NORMALIZACIÓN
    # =========================
    if not surface:
        surface.append("Superficie ofensiva reducida (madurez alta)")
        exposure = "LOW"
    else:
        exposure = (
            "HIGH" if weight >= 7 else
            "MEDIUM" if weight >= 3 else
            "LOW"
        )

    return {
        "exposure_level": exposure,
        "signal_weight": weight,
        "vectors": surface
    }


def correlate_historical_cves(http, tls, dns):
    """
    Correlación pasiva de tecnologías detectadas vs CVEs históricas conocidas.
    No escanea, no explota, no enumera versiones activamente.
    Enfoque: señal histórica + contexto de riesgo.
    """
    score = 0
    signals = set()

    # =========================
    # NORMALIZACIÓN DE FUENTES
    # =========================
    headers = http.get("headers", {}) if isinstance(http, dict) else {}
    dns = dns if isinstance(dns, dict) else {}
    tls = tls if isinstance(tls, dict) else {}

    tech_sources = []

    # --- HTTP stack ---
    for h in ["Server", "X-Powered-By", "Via"]:
        val = headers.get(h)
        if val:
            tech_sources.append(val)

    # --- TLS stack ---
    proto = tls.get("protocol")
    cipher = tls.get("cipher")

    if proto:
        tech_sources.append(f"TLS-{proto}")
    if cipher:
        tech_sources.append(cipher)

    # --- DNS hints ---
    for cname in dns.get("CNAME", []):
        tech_sources.append(cname)

    # =========================
    # HEURÍSTICA CVE HISTÓRICA
    # =========================
    for tech in tech_sources:
        t = tech.lower()

        # --- Web servers ---
        if "apache" in t:
            signals.add("Apache históricamente afectado por CVEs críticas (RCE, traversal)")
            score += 10

        if "nginx" in t:
            signals.add("NGINX correlaciona con request smuggling y parsing flaws")
            score += 8

        if "iis" in t or "microsoft-httpapi" in t:
            signals.add("IIS ha tenido CVEs de desbordamiento y auth bypass")
            score += 9

        # --- Lenguajes / runtimes ---
        if "php" in t:
            signals.add("PHP correlaciona con RCE, type juggling, deserialización")
            score += 12

        if "java" in t or "tomcat" in t:
            signals.add("Java/Tomcat correlaciona con deserialización y traversal")
            score += 11

        # --- TLS / Crypto ---
        if "tls-1.0" in t or "tls-1.1" in t:
            signals.add("TLS legacy asociado a CVEs criptográficas históricas")
            score += 15

        if "openssl" in t:
            signals.add("OpenSSL históricamente afectado por memory corruption")
            score += 10

        if "cbc" in t or "sha1" in t:
            signals.add("Cifrado débil correlaciona con ataques conocidos")
            score += 8

        # --- Infra / CDN ---
        if "cloudflare" in t:
            signals.add("CDN mitiga CVEs comunes y reduce superficie directa")
            score -= 6

        if "akamai" in t or "fastly" in t:
            signals.add("CDN enterprise reduce exposición a CVEs genéricas")
            score -= 5

    # =========================
    # NORMALIZACIÓN SCORE
    # =========================
    if score < 0:
        score = 0

    if score >= 30:
        verdict = "HIGH"
    elif score >= 15:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return {
        "verdict": verdict,
        "risk_score": score,
        "signals": list(signals) if signals else ["No correlaciones CVE históricas relevantes"]
    }


def recon_url():
    while True:
        # =========================
        # LIMPIEZA DE CONSOLA
        # =========================
        try:
            console.clear()
        except Exception:
            pass

        # =========================
        # HEADER VIVO · ZEN · TECH
        # =========================
        header = Text(justify="center")
        header.append("🔍  RECON  INVERSO  DE  URLS\n", style="bold bright_magenta")
        header.append("Modo Ingeniero  ", style="dim white")
        header.append("•  ", style="bright_black")
        header.append("OSINT  ", style="dim cyan")
        header.append("•  ", style="bright_black")
        header.append("Inversión Técnica\n", style="dim blue")
        header.append("Autor: ", style="dim white")
        header.append("ByMakaveli", style="bold bright_cyan")

        console.print(Panel(
            header,
            border_style="bright_magenta",
            padding=(1, 6),
            title="⧉ PROTOCOLO DE OBSERVACIÓN ⧉",
            title_align="center"
        ))

        # =========================
        # INPUT HARDENING
        # =========================
        try:
            raw = Prompt.ask("🌐 URL o dominio").strip()
            if not raw:
                raise ValueError("Entrada vacía")

            url = normalize_url(raw)
            domain = extract_domain(url)

        except Exception as e:
            console.print(Panel(
                f"❌ Error en la entrada\n\n{e}",
                style="bold red"
            ))
            Prompt.ask("\nENTER para continuar")
            continue

        # =========================
        # RATE LIMIT / SIGILO
        # =========================
        try:
            rate_limit(domain)
        except Exception:
            pass

        # =========================
        # PIPELINE DE RECON AISLADO
        # =========================
        http, dns, tls, whois_data = {}, {}, {}, {}
        tls_fp = {}
        cdn_info = {}
        asn_info = {}
        infra_corr = {}
        failures = []
        cve_corr = {}
        off_surface = {}


        # --- HTTP ---
        try:
            http = analyze_http(url)
            if "error" in http:
                failures.append("HTTP")
        except Exception as e:
            http = {"error": str(e)}
            failures.append("HTTP")

        # --- DNS ---
        try:
            dns = analyze_dns(domain)
            if not dns:
                failures.append("DNS")
        except Exception as e:
            dns = {"error": str(e)}
            failures.append("DNS")

        # --- TLS ---
        try:
            tls = analyze_tls(domain)
            if "error" in tls:
                failures.append("TLS")
        except Exception as e:
            tls = {"error": str(e)}
            failures.append("TLS")

        # --- TLS Fingerprint ---
        try:
            tls_fp = analyze_tls_fingerprint(tls)
        except Exception as e:
            tls_fp = {"error": str(e)}

        # --- CDN Detection ---
        try:
            cdn_info = detect_cdn_vs_origin(domain, dns, tls)
        except Exception as e:
            cdn_info = {"error": str(e)}

        # --- ASN (si existe el módulo) ---
        try:
            if "analyze_asn" in globals():
                asn_info = analyze_asn(domain)
        except Exception:
            asn_info = {}

        # --- CORRELACIÓN INFRA AVANZADA ---
        try:
            infra_corr = correlate_cdn_ja3_asn(
                domain=domain,
                dns=dns,
                tls=tls,
                tls_fp=tls_fp,
                asn_info=asn_info
            )
        except Exception as e:
            infra_corr = {"error": str(e)}

        # --- WHOIS ---
        try:
            whois_data = analyze_whois(domain)
            if "error" in whois_data:
                failures.append("WHOIS")
        except Exception as e:
            whois_data = {"error": str(e)}
            failures.append("WHOIS")
            
        # --- CORRELACIÓN CVE HISTÓRICA ---
        try:
            cve_corr = correlate_historical_cves(http, tls, dns)
        except Exception as e:
            cve_corr = {"error": str(e)}

# --- SUPERFICIE OFENSIVA ABSTRACTA ---
        try:
            off_surface = analyze_offensive_surface(
            http=http,
            dns=dns,
            tls=tls,
            cdn_info=cdn_info,
        asn_info=asn_info
        )
        except Exception as e:
            off_surface = {"error": str(e)}
    

        # =========================
        # SCORING ANTI-FRÁGIL
        # =========================
        try:
            score, notes = trust_score(http, tls, whois_data, dns)
        except Exception as e:
            score, notes = 0, [f"Error en scoring: {e}"]

        # =========================
        # CRITERIO ENTERPRISE
        # =========================
        try:
            criteria = generate_enterprise_criteria(
                http=http,
                dns=dns,
                tls=tls,
                whois_data=whois_data,
                score=score
            )
        except Exception as e:
            criteria = {"error": str(e)}

        # =========================
        # OUTPUT VISUAL · FORENSE
        # =========================
        show_table("🌐 HTTP / TECNOLOGÍA", http)
        show_table("🧬 DNS / INFRAESTRUCTURA", dns)
        show_table("🔐 TLS / CRIPTOGRAFÍA", tls)
        show_table("🧬 TLS FINGERPRINT (JA3 / JA4)", tls_fp)
        show_table("🌐 CDN vs ORIGIN", cdn_info)
        show_table("🧠 CORRELACIÓN CDN · TLS · ASN", infra_corr)
        show_table("🧾 IDENTIDAD (WHOIS)", whois_data)
        show_table("🧬 CVE HISTÓRICAS (CORRELACIÓN PASIVA)", cve_corr)
        show_table("👁️ SUPERFICIE OFENSIVA (LECTURA INVERSA)", off_surface)


        # =========================
        # TRUST PANEL
        # =========================
        score_style = (
            "bold green" if score >= 80 else
            "bold yellow" if score >= 40 else
            "bold red"
        )

        console.print(Panel(
            f"🧠 TRUST SCORE: {score}/100\n\n" +
            ("\n".join(f"• {n}" for n in notes) if notes else "Sin alertas críticas"),
            style=score_style
        ))

        # =========================
        # PANEL ESTRATÉGICO ENTERPRISE
        # =========================
        if criteria and "error" not in criteria:
            console.print(Panel(
                f"🏗️ MADUREZ: {criteria.get('maturity','?').upper()}\n"
                f"🧠 POSTURA: {criteria.get('posture','?').upper()}",
                style="bold bright_blue"
            ))

            if criteria.get("defensive"):
                console.print(Panel(
                    "🛡️ RECOMENDACIONES DEFENSIVAS:\n" +
                    "\n".join(f"• {d}" for d in criteria["defensive"]),
                    style="green"
                ))

            if criteria.get("offensive_surface"):
                console.print(Panel(
                    "👁️ LECTURA INVERSA (ABSTRACTA):\n" +
                    "\n".join(f"• {o}" for o in criteria["offensive_surface"]),
                    style="yellow"
                ))

            if criteria.get("strategic_notes"):
                console.print(Panel(
                    "📐 NOTAS ESTRATÉGICAS:\n" +
                    "\n".join(f"• {n}" for n in criteria["strategic_notes"]),
                    style="dim cyan"
                ))

        # =========================
        # LECTURA INVERSA · HUMANA
        # =========================
        lectura = [
            "No mide si puedes atacar",
            "Mide si este dominio se cuida",
            "Infra limpia = madurez operativa",
            "Caos técnico = improvisación",
            "El silencio también comunica"
        ]

        if failures:
            lectura.append("")
            lectura.append("⚠️ MÓDULOS INCOMPLETOS:")
            lectura.extend(f"- {f}" for f in failures)

        console.print(Panel(
            "📌 LECTURA INVERSA:\n" + "\n".join(f"- {l}" for l in lectura),
            style="bold cyan"
        ))

        # =========================
        # CONTROL DE FLUJO FINAL
        # =========================
        try:
            if Confirm.ask("\n🔁 ¿Deseas analizar otra URL?", default=True):
                continue
            console.print(Panel(
                "👁️ Cierre consciente del operador\n"
                "La observación termina, el criterio permanece.",
                style="dim white"
            ))
            break
        except KeyboardInterrupt:
            console.print("\n👋 Salida forzada por el operador")
            break
        except Exception:
            break



def zen_intro():
    global _stop_animation

    title = "ByMakaveli"
    subtitle = "code  •  psychology  •  recon"
    philosophy = "observe quietly — decide precisely"
    hint = "⏎ presiona ENTER para continuar"

    neon_layers = [
        ("bright_magenta", 0),
        ("bright_blue", 1),
        ("bright_cyan", 2),
        ("white", 3),
    ]

    glow_colors = [
        "bright_magenta",
        "bright_blue",
        "bright_cyan",
        "green",
        "yellow",
        "white",
    ]

    t = 0.0

    while not _stop_animation:
        try:
            console.clear()
        except Exception:
            pass

        # respiración + pulso
        breath = (math.sin(t) + 1) / 2
        pulse = (math.sin(t * 1.7) + 1) / 2
        idx = int(breath * (len(glow_colors) - 1))
        glow = glow_colors[idx]

        console.print("\n\n")

        # ===== TÍTULO NEÓN MULTICAPA =====
        for color, offset in neon_layers:
            style = f"bold {color}" if offset == 3 else f"{color}"
            console.print(
                Text(" " * offset + title, style=style),
                justify="center"
            )

        console.print()

        # ===== SUBTÍTULO VIVO =====
        subtitle_style = f"{glow}"
        console.print(
            Text(subtitle, style=subtitle_style),
            justify="center"
        )

        console.print()

        # ===== FILOSOFÍA ZEN =====
        console.print(
            Text(philosophy, style=f"dim {glow}"),
            justify="center"
        )

        console.print("\n")

        # ===== HINT SUAVE INTERMITENTE =====
        if pulse > 0.35:
            console.print(
                Text(hint, style="dim italic white"),
                justify="center"
            )

        time.sleep(0.07)
        t += 0.10


def zen_gate():
    global _stop_animation
    _stop_animation = False

    anim = threading.Thread(target=zen_intro, daemon=True)
    anim.start()

    try:
        input()  # ENTER
    except KeyboardInterrupt:
        pass

    _stop_animation = True
    time.sleep(0.18)

    try:
        console.clear()
    except Exception:
        pass

    console.print(Panel(
        Text(
            "🧠 Estado: ENFOQUE ACTIVADO\n"
            "🔍 Modo: Recon consciente\n"
            "⚙️ Flujo: Estable\n\n"
            "El poder entra en silencio.",
            style="bold bright_cyan",
            justify="center"
        ),
        border_style="bright_magenta",
        padding=(1, 6),
        title="⧉ TRANSICIÓN ⧉",
        title_align="center"
    ))



# =========================
# ENTRYPOINT
# =========================

if __name__ == "__main__":
    zen_gate()
    recon_url()
