#!/usr/bin/env python3
from prometheus_client import start_http_server, Gauge
import urllib.request
import time

dsvw_up = Gauge("dsvw_up", "DSVW reachable on :65412")
dssw_up = Gauge("dssw_up", "DSSW reachable on :65413")

def probe(url, gauge):
    try:
        urllib.request.urlopen(url, timeout=2)
        gauge.set(1)
    except Exception:
        gauge.set(0)

if __name__ == "__main__":
    start_http_server(9093)
    print("dssw_exporter listening on :9093")
    while True:
        probe("http://127.0.0.1:65412/", dsvw_up)
        probe("http://127.0.0.1:65413/", dssw_up)
        time.sleep(15)
