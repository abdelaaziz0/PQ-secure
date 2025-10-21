#!/bin/bash
echo "=== Analyse des Benchmarks PQ-Secure Sync ==="
echo ""

if [ ! -f benchmarks/benchmark_*.json ]; then
    echo "❌ Aucun benchmark trouvé. Lancez d'abord:"
    echo "   PYTHONPATH=. python main.py benchmark --kem Kyber768 --sig Dilithium3"
    exit 1
fi

# Trouver le fichier le plus récent
LATEST=$(ls -t benchmarks/benchmark_*.json | head -1)

echo "📊 Fichier: $LATEST"
echo ""

# Extraire les métriques importantes
python3 << PYTHON
import json

with open("$LATEST") as f:
    results = json.load(f)

for i, result in enumerate(results, 1):
    print(f"═══ Test {i}: {result['kem_algorithm']} + {result['sig_algorithm']} ═══")
    print(f"  ⏱️  Handshake:     {result['metrics']['avg_handshake_ms']:.2f} ms")
    print(f"  🔑 Keygen:        {result['metrics']['avg_keygen_ms']:.2f} ms")
    print(f"  🖥️  CPU:           {result['metrics']['cpu_usage_avg']:.1f}%")
    print(f"  💾 Mémoire:       {result['metrics']['memory_mb_avg']:.1f} MB")
    print(f"  📦 Clé publique:  {result['metrics']['public_key_size']} bytes")
    print(f"  ✍️  Signature:     {result['metrics']['signature_size']} bytes")
    print()
PYTHON

echo "✅ Analyse terminée"
echo ""
echo "📁 Fichiers générés:"
ls -lh benchmarks/
