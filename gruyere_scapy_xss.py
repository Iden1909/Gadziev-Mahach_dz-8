#!/usr/bin/env python3
"""
Скрипт для перехвата HTTP-трафика при работе с Google Gruyere
и анализа XSS-эксплуатации с помощью Scapy.

Поддерживает две операции:
  1) live-перехват трафика во время работы с Gruyere в браузере
     (сохраняет .pcap и печатает разобранные HTTP-запросы/ответы)
  2) анализ уже сохранённого .pcap-файла (--analyze)

Работает на macOS. Перед запуском перехвата нужны права root (sudo),
т.к. Scapy открывает raw-сокет.

Пример запуска перехвата (подставьте ваш интерфейс, обычно en0 для Wi-Fi):
    sudo python3 gruyere_scapy_xss.py --iface en0 --port 8008 --out capture.pcap

Пример анализа сохранённого файла:
    python3 gruyere_scapy_xss.py --analyze capture.pcap
"""

import argparse
import gzip
import io
import re
import sys

from scapy.all import sniff, wrpcap, rdpcap, TCP, IP, Raw


# ---------------------------------------------------------------------------
# Разбор "сырых" TCP-сегментов в HTTP-сообщения
# ---------------------------------------------------------------------------

def is_http_payload(payload: bytes) -> bool:
    """Грубая проверка: похоже ли начало payload на HTTP-запрос или ответ."""
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"HTTP/")
    return payload[:8].startswith(methods) or payload.startswith(b"HTTP/")


def split_headers_body(payload: bytes):
    """Делит HTTP-сообщение на (заголовки_текст, тело_bytes)."""
    sep = b"\r\n\r\n"
    idx = payload.find(sep)
    if idx == -1:
        return payload.decode(errors="replace"), b""
    head = payload[:idx].decode(errors="replace")
    body = payload[idx + len(sep):]
    return head, body


def maybe_gunzip(body: bytes, headers_text: str) -> bytes:
    """
    Доработка для корректного отображения содержимого ответа:
    если сервер прислал Content-Encoding: gzip, тело нужно разжать
    перед тем, как печатать/искать в нём payload XSS.
    """
    if "content-encoding" in headers_text.lower() and "gzip" in headers_text.lower():
        try:
            return gzip.GzipFile(fileobj=io.BytesIO(body)).read()
        except OSError:
            # Тело могло быть обрезано на границе пакета — вернём как есть
            return body
    return body


def describe_packet(pkt, xss_markers=None):
    """Печатает разбор одного HTTP-пакета: метод/URL/заголовки/тело."""
    if not pkt.haslayer(Raw):
        return
    payload = bytes(pkt[Raw].load)
    if not is_http_payload(payload):
        return

    headers_text, body = split_headers_body(payload)
    lines = headers_text.split("\r\n")
    start_line = lines[0] if lines else ""

    src = f"{pkt[IP].src}:{pkt[TCP].sport}" if pkt.haslayer(IP) else "?"
    dst = f"{pkt[IP].dst}:{pkt[TCP].dport}" if pkt.haslayer(IP) else "?"

    print("=" * 70)
    print(f"{src} -> {dst}")
    print(start_line)
    for h in lines[1:]:
        if h:
            print(f"  {h}")

    if body:
        decoded_body = maybe_gunzip(body, headers_text)
        text_body = decoded_body.decode(errors="replace")
        snippet = text_body[:500]
        print("-- тело (первые 500 симв.) --")
        print(snippet)

        if xss_markers:
            full_text = headers_text + "\n" + text_body
            for marker in xss_markers:
                if marker in full_text:
                    print(f"[!] НАЙДЕН МАРКЕР XSS: {marker!r}")


# ---------------------------------------------------------------------------
# Режим live-перехвата
# ---------------------------------------------------------------------------

def run_capture_simple(iface: str, port: int, out_file: str, xss_markers):
    bpf_filter = f"tcp port {port}"
    print(f"[*] Перехват трафика на интерфейсе {iface}, фильтр: '{bpf_filter}'")
    print("[*] Взаимодействуйте с Gruyere в браузере. Остановка: Ctrl+C")

    def on_packet(pkt):
        describe_packet(pkt, xss_markers)

    packets = sniff(iface=iface, filter=bpf_filter, prn=on_packet, store=True)
    wrpcap(out_file, packets)
    print(f"\n[*] Сохранено {len(packets)} пакетов в {out_file}")


# ---------------------------------------------------------------------------
# Режим анализа сохранённого .pcap
# ---------------------------------------------------------------------------

def run_analyze(pcap_file: str, xss_markers):
    print(f"[*] Анализ файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Всего пакетов в файле: {len(packets)}")

    http_count = 0
    xss_hits = []

    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        payload = bytes(pkt[Raw].load)
        if not is_http_payload(payload):
            continue
        http_count += 1

        headers_text, body = split_headers_body(payload)
        decoded_body = maybe_gunzip(body, headers_text)
        full_text = headers_text + "\n" + decoded_body.decode(errors="replace")

        found_markers = [m for m in xss_markers if m in full_text] if xss_markers else []
        if found_markers:
            xss_hits.append((pkt, headers_text, decoded_body, found_markers))

        describe_packet(pkt, xss_markers)

    print("\n" + "#" * 70)
    print(f"ИТОГО HTTP-сообщений: {http_count}")
    print(f"ИТОГО сообщений с маркерами XSS: {len(xss_hits)}")
    for i, (pkt, headers_text, body, markers) in enumerate(xss_hits, 1):
        print(f"\n--- XSS-находка #{i} ---")
        print(f"Маркеры: {markers}")
        print(headers_text.split('\r\n')[0])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

DEFAULT_XSS_MARKERS = [
    "<script>",
    "alert(",
    "onerror=",
    "onload=",
    "<img src=x",
]


def main():
    parser = argparse.ArgumentParser(description="Scapy: перехват и анализ HTTP для Google Gruyere / XSS")
    parser.add_argument("--iface", default="en0", help="Сетевой интерфейс для перехвата (macOS: en0 обычно Wi-Fi)")
    parser.add_argument("--port", type=int, default=8008, help="Порт Gruyere (по умолчанию 8008)")
    parser.add_argument("--out", default="capture.pcap", help="Файл для сохранения перехваченного трафика")
    parser.add_argument("--analyze", metavar="PCAP_FILE", help="Вместо перехвата — проанализировать существующий .pcap")
    parser.add_argument("--marker", action="append", help="Доп. строка-маркер для поиска XSS (можно указывать несколько раз)")
    args = parser.parse_args()

    xss_markers = list(DEFAULT_XSS_MARKERS)
    if args.marker:
        xss_markers.extend(args.marker)

    if args.analyze:
        run_analyze(args.analyze, xss_markers)
    else:
        run_capture_simple(args.iface, args.port, args.out, xss_markers)


if __name__ == "__main__":
    main()
