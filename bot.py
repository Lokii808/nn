#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import concurrent.futures
from urllib.parse import urlparse

# ================== CONFIG ==================
WORDLIST = "/home/kali/ferramentas/fuzz/common.txt"
FFUF_BIN = "ffuf"
THREADS = "10"
HOSTS_PARALELOS = 3
TIMEOUT = "3"
MAXTIME = "200"

LIMIAR_MUITOS = 50
AMOSTRA_MUITOS = 5
AMOSTRA_POUCOS = 15
LIMITE_RUIDO = 200

XSS_BIN = "xss"
NUCLEI_BIN = "nuclei"
NOTIFY_BIN = "notify"
NUCLEI_TEMPLATES = "/home/ferramentas/paths/privados/"
NUCLEI_CONC = "10"

FIREFOX_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)
HEADERS = [
    f"User-Agent: {FIREFOX_UA}",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding: gzip, deflate, br",
    "Connection: keep-alive",
    "Upgrade-Insecure-Requests: 1",
    "Sec-Fetch-Dest: document",
    "Sec-Fetch-Mode: navigate",
    "Sec-Fetch-Site: none",
    "Sec-Fetch-User: ?1",
]
# ============================================


def log(msg):
    print(f"[+] {msg}", flush=True)


def erro(msg):
    print(f"[-] {msg}", flush=True)


def normalizar_url(url):
    url = url.strip()
    if not url:
        return None
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    return url


def montar_headers():
    partes = []
    for h in HEADERS:
        h_escapado = h.replace("'", "'\\''")
        partes.append(f"-H '{h_escapado}'")
    return " ".join(partes)


def parse_ffuf_json_output(texto_json):
    """Extrai paths do JSON do ffuf, IGNORANDO qualquer coisa com FUZZ."""
    paths = set()
    try:
        data = json.loads(texto_json)
    except Exception as e:
        erro(f"Erro parseando JSON do ffuf: {e}")
        return paths

    for r in data.get("results", []):
        inp = r.get("input", {})
        if isinstance(inp, dict):
            val = inp.get("FUZZ", "")
        else:
            val = str(inp)
        val = val.strip().lstrip("/")

        # >>> IGNORA qualquer path que contenha FUZZ (placeholder)
        if not val or "FUZZ" in val.upper() or "FUZZ" in val:
            continue

        paths.add(val)

        u = r.get("url", "")
        if u:
            p = urlparse(u).path.lstrip("/")
            # >>> IGNORA também na URL
            if p and "FUZZ" not in p.upper() and "FUZZ" not in p:
                paths.add(p)
    return paths


def rodar_ffuf_host(url):
    """Roda ffuf, captura JSON do stdout e retorna URLs reais (sem FUZZ)."""
    base = url.rstrip("/")

    cmd = (
        f"{FFUF_BIN} -u '{base}/FUZZ' "
        f"-w {WORDLIST} "
        f"{montar_headers()} "
        f"-ac -t {THREADS} -timeout {TIMEOUT} -maxtime {MAXTIME} "
        f"-of json -o /dev/stdout -s"
    )

    # >>> NÃO loga mais a linha FFUF -> .../FUZZ
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=int(MAXTIME) + 30)
    except subprocess.TimeoutExpired:
        erro(f"[{url}] ffuf timeout")
        return (url, [])
    except Exception as e:
        erro(f"[{url}] ffuf erro: {e}")
        return (url, [])

    out = proc.stdout.strip()
    if not out:
        return (url, [])

    idx = out.find("{")
    if idx == -1:
        return (url, [])
    texto_json = out[idx:]

    paths = parse_ffuf_json_output(texto_json)
    if not paths:
        return (url, [])

    urls_completas = [f"{base}/{p}" for p in sorted(paths)]
    linhas = len(urls_completas)

    if linhas > LIMITE_RUIDO:
        log(f"[{url}] [!] muito ruído ({linhas}) -> descartado")
        return (url, [])

    # >>> Só loga hit se tiver path REAL (já filtrado FUZZ)
    log(f"[{url}] [+] {linhas} hits (em memória)")
    for i, u in enumerate(urls_completas, start=1):
        log(f"       [{i}] {u}")

    return (url, urls_completas)


def amostrar_urls(urls):
    total = len(urls)
    if total > LIMIAR_MUITOS:
        amostra = urls[:AMOSTRA_MUITOS]
        log(f"Amostragem: {total} > {LIMIAR_MUITOS} -> {len(amostra)} primeiras")
    else:
        amostra = urls[:AMOSTRA_POUCOS]
        log(f"Amostragem: {total} <= {LIMIAR_MUITOS} -> {len(amostra)} primeiras")
    return amostra


def rodar_scanners(urls_amostra, host):
    """Manda as URLs via stdin para xss e nuclei (sem arquivos)."""
    if not urls_amostra:
        return

    payload = "\n".join(urls_amostra) + "\n"

    log("=" * 60)
    log(f"URLs COMPLETAS enviadas ao XSS para {host}:")
    for i, u in enumerate(urls_amostra, start=1):
        log(f"   [{i}] {u}")
    log("=" * 60)

    log(f"Rodando xss para {host}...")
    try:
        subprocess.run(f"{XSS_BIN}", shell=True, input=payload, text=True)
    except Exception as e:
        erro(f"xss erro: {e}")

    log(f"URLs COMPLETAS enviadas ao NUCLEI para {host}:")
    for i, u in enumerate(urls_amostra, start=1):
        log(f"   [{i}] {u}")

    log(f"Rodando nuclei para {host}...")
    cmd_nuclei = (
        f"{NUCLEI_BIN} -t {NUCLEI_TEMPLATES} -l /dev/stdin "
        f"-c {NUCLEI_CONC} | {NOTIFY_BIN}"
    )
    try:
        subprocess.run(cmd_nuclei, shell=True, input=payload, text=True)
    except Exception as e:
        erro(f"nuclei erro: {e}")


def main():
    if len(sys.argv) < 2:
        erro("Uso: python3 scanner.py <arquivo.txt>")
        sys.exit(1)

    arquivo = sys.argv[1]

    if not os.path.isfile(arquivo):
        erro(f"Arquivo não encontrado: {arquivo}")
        sys.exit(1)

    if not os.path.isfile(WORDLIST):
        erro(f"Wordlist não encontrada: {WORDLIST}")
        sys.exit(1)

    urls = []
    vistas = set()
    with open(arquivo, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            u = normalizar_url(linha)
            if not u or u in vistas:
                continue
            vistas.add(u)
            urls.append(u)

    if not urls:
        erro("Nenhuma URL válida no arquivo.")
        sys.exit(1)

    log(f"{len(urls)} URLs válidas para fuzz.")
    log(f"Wordlist: {WORDLIST}")
    log(f"Paralelismo: {HOSTS_PARALELOS} hosts | Threads ffuf: {THREADS}")

    resultados_por_host = {}
    total_hits = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=HOSTS_PARALELOS) as ex:
        futuros = {ex.submit(rodar_ffuf_host, u): u for u in urls}
        for fut in concurrent.futures.as_completed(futuros):
            url = futuros[fut]
            try:
                u, lista = fut.result()
            except Exception as e:
                erro(f"[{url}] erro: {e}")
                continue
            resultados_por_host[u] = lista
            total_hits += len(lista)

    log(f"FFUF finalizado. Total de hits: {total_hits}")

    for host, lista in resultados_por_host.items():
        if not lista:
            continue
        log("=" * 60)
        log(f"Processando scanners para {host} ({len(lista)} URLs)")
        log("=" * 60)

        amostra = amostrar_urls(lista)
        if not amostra:
            continue

        rodar_scanners(amostra, host)

    log("Finalizado! 🚀")


if __name__ == "__main__":
    main()
