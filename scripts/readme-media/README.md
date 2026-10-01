# Imágenes del README

Regenera `docs/media/` (GIF y capturas) con la **interfaz web real** y **datos ficticios**:

```bash
npm i --no-save puppeteer-core --prefix scripts/readme-media   # una vez (o PUPPETEER_DIR=<carpeta con node_modules>)
scripts/readme-media/run.sh                                     # PORT=8766 por omisión
```

- `demo_server.py` arranca `create_app` sobre una base y una caché temporales, con redes, activos, credenciales y
  token inventados. El escaneo y el envío a iurefficient están simulados: **no se escanea ninguna red** ni se
  conecta a nada. La clasificación la calcula el clasificador real.
- `capture.mjs` conduce la interfaz en Chromium headless (1280×800, escala 1.5) y dibuja las ilustraciones de
  producto (planas, propias).
- `run.sh` arma el GIF (ffmpeg, paleta en dos pasadas) y comprime las capturas con `pngquant`.

La interfaz solo está en español, así que ambos README usan las mismas imágenes (`*-es`).
