"""Unsupervised log-line anomaly detection with a small PyTorch autoencoder (AMD GPU via ROCm, else CPU).

Each line becomes a handful of numeric features (length, character mix, entropy, IPs, ports, hex
blobs, error words …). An autoencoder is trained on the file itself — "normal" for this log — and
lines it reconstructs worst (error above mean + 3·std) are reported. It needs no labels and no
internet, so it complements the regex threat patterns: it surfaces the odd one-off lines a human
would want to read first. Without PyTorch the analysis simply has no ML section.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Optional, Sequence

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)
PORT_RE = re.compile(r"(?:port[ =:]|:)(\d{2,5})\b", re.I)
HEX_RE = re.compile(r"\b(?:0x)?[0-9a-f]{16,}\b", re.I)
ERROR_RE = re.compile(r"\b(error|fail(?:ed|ure)?|denied|invalid|refused|critical|fatal|panic|segfault|unauthori[sz]ed)\b",
                      re.I)
MAX_LINES = 200_000
FEATURE_NAMES = ["length", "digits", "upper", "special", "entropy", "tokens", "mean_token", "ips", "ports",
                 "hex_blobs", "error_words"]


def featurize(line: str) -> List[float]:
    n = len(line) or 1
    tokens = line.split()
    counts = Counter(line)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values()) if line else 0.0
    return [
        math.log1p(len(line)),
        sum(ch.isdigit() for ch in line) / n,
        sum(ch.isupper() for ch in line) / n,
        sum(not ch.isalnum() and not ch.isspace() for ch in line) / n,
        entropy,
        math.log1p(len(tokens)),
        math.log1p(sum(map(len, tokens)) / len(tokens)) if tokens else 0.0,
        float(len(IP_RE.findall(line))),
        float(len(PORT_RE.findall(line))),
        float(len(HEX_RE.findall(line))),
        float(len(ERROR_RE.findall(line))),
    ]


def find_anomalies(lines: Sequence[str], top_k: int = 10, min_lines: int = 50, epochs: int = 80,
                   device=None, seed: int = 0) -> Optional[Dict[str, object]]:
    """{"device", "lines", "threshold", "anomalies": [{"line_no", "score", "line"}]} or None without PyTorch."""
    try:
        import torch
        from torch import nn
    except ImportError:
        return None
    from core.accelerator import torch_device

    lines = list(lines[:MAX_LINES])
    device = device or torch_device() or torch.device("cpu")
    result: Dict[str, object] = {"device": str(device), "lines": len(lines), "threshold": None, "anomalies": []}
    if len(lines) < min_lines:
        return result

    torch.manual_seed(seed)
    x = torch.tensor([featurize(line) for line in lines], dtype=torch.float32)
    mean, std = x.mean(0), x.std(0).clamp_min(1e-6)
    x = ((x - mean) / std).to(device)
    width = x.shape[1]
    model = nn.Sequential(nn.Linear(width, 8), nn.ReLU(), nn.Linear(8, 3), nn.ReLU(),
                          nn.Linear(3, 8), nn.ReLU(), nn.Linear(8, width)).to(device)
    optimiser = torch.optim.Adam(model.parameters(), lr=1e-2)
    batch = 4096
    for _ in range(epochs):
        for start in range(0, x.shape[0], batch):
            chunk = x[start:start + batch]
            optimiser.zero_grad()
            loss = ((model(chunk) - chunk) ** 2).mean()
            loss.backward()
            optimiser.step()
    with torch.no_grad():
        errors = ((model(x) - x) ** 2).mean(1).cpu()
    threshold = float(errors.mean() + 3 * errors.std())
    result["threshold"] = round(threshold, 4)
    order = torch.argsort(errors, descending=True)[:top_k].tolist()
    result["anomalies"] = [{"line_no": i + 1, "score": round(float(errors[i]), 4), "line": lines[i][:300]}
                           for i in order if float(errors[i]) > threshold]
    return result
