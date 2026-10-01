#!/usr/bin/env bash
# Regenera docs/media/ (GIF y capturas del README) con la interfaz real y datos ficticios.
# Requiere: uv, node, ffmpeg, pngquant, Chromium (CHROME=...) y puppeteer-core
# (`npm i --no-save puppeteer-core` en esta carpeta, o PUPPETEER_DIR=<carpeta con node_modules>).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PORT="${PORT:-8766}"
DATA="${DATA:-$(mktemp -d)}"
MEDIA="$ROOT/docs/media"
rm -rf "$DATA"; mkdir -p "$DATA" "$MEDIA"

cd "$ROOT"
DEMO_SPEED="${DEMO_SPEED:-1.6}" uv run python "$HERE/demo_server.py" --data "$DATA" --port "$PORT" &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -sf -H 'X-Iureti-UI: 1' "http://127.0.0.1:$PORT/api/status" >/dev/null && break; sleep 0.2; done

DATA="$DATA" PORT="$PORT" node "$HERE/capture.mjs"
CAP="$DATA/cap"

# GIF: dos pasadas con paleta (cuadros con su duración real, ~900 px, 12 fps)
( cd "$CAP" && ffmpeg -loglevel error -y -f concat -safe 0 -i hero.txt \
    -vf "fps=12,scale=900:-1:flags=lanczos,palettegen=stats_mode=diff" palette.png && \
  ffmpeg -loglevel error -y -f concat -safe 0 -i hero.txt -i palette.png \
    -lavfi "fps=12,scale=900:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5" -loop 0 hero.gif )
# La interfaz solo existe en español: ambos README usan las mismas imágenes (-es)
cp "$CAP/hero.gif" "$MEDIA/hero-es.gif"

for n in scan assets detail settings; do
  ffmpeg -loglevel error -y -i "$CAP/$n.png" -vf "scale=1600:-1:flags=lanczos" "$CAP/$n-1600.png"
  pngquant --quality 70-90 --force --output "$MEDIA/$n-es.png" "$CAP/$n-1600.png"
done
ls -la "$MEDIA"
