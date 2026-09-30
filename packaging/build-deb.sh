#!/bin/bash
# Construye el .deb de iureti-discovery con su propio Python (no depende del Python del sistema).
# Se ejecuta DENTRO de un contenedor debian:12 de la arquitectura destino (amd64 o arm64):
#   docker run --rm -v "$PWD":/src -w /src debian:12 bash packaging/build-deb.sh
# El entorno se arma directamente en /opt/iureti (la ruta final), así las rutas absolutas del venv son válidas.
set -euo pipefail

SRC=${SRC:-/src}
OUT=${OUT:-$SRC/dist}
PY=${PY:-3.12}
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl dpkg-dev >/dev/null

if ! command -v uv >/dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin INSTALLER_NO_MODIFY_PATH=1 sh >/dev/null
fi

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/pyproject.toml" | head -1)
ARCH=$(dpkg --print-architecture)
echo ">> iureti-discovery $VERSION ($ARCH)"

rm -rf /opt/iureti
export UV_PYTHON_INSTALL_DIR=/opt/iureti/python UV_PYTHON_PREFERENCE=only-managed UV_NO_CACHE=1
uv python install "$PY"
uv venv --python "$PY" /opt/iureti/venv

WORK=$(mktemp -d)
cp -a "$SRC/pyproject.toml" "$SRC/uv.lock" "$SRC/README.md" "$SRC/src" "$WORK/"
(cd "$WORK" && uv export --frozen --no-dev --no-emit-project --format requirements-txt -o requirements.txt >/dev/null \
    && uv build --wheel -o "$WORK/dist" >/dev/null)
uv pip install --python /opt/iureti/venv/bin/python -r "$WORK/requirements.txt"
uv pip install --python /opt/iureti/venv/bin/python --no-deps "$WORK"/dist/*.whl
/opt/iureti/venv/bin/iureti-discovery --version

# Adelgazar: pruebas y cachés de bytecode del intérprete
find /opt/iureti -type d \( -name __pycache__ -o -name tests -o -name test \) -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf /opt/iureti/python/*/lib/python*/idlelib /opt/iureti/python/*/lib/python*/tkinter /opt/iureti/python/*/lib/python*/turtledemo

PKG="$WORK/pkg"
mkdir -p "$PKG/DEBIAN" "$PKG/opt" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$PKG/etc/default"
cp -a /opt/iureti "$PKG/opt/"
install -m 0755 "$SRC/packaging/deb/iureti-discovery-wrapper" "$PKG/usr/bin/iureti-discovery"
install -m 0644 "$SRC/packaging/systemd/iureti-discovery.service" "$PKG/lib/systemd/system/"
install -m 0644 "$SRC/packaging/deb/default" "$PKG/etc/default/iureti-discovery"
install -m 0755 "$SRC/packaging/deb/postinst" "$SRC/packaging/deb/prerm" "$SRC/packaging/deb/postrm" "$PKG/DEBIAN/"
echo "/etc/default/iureti-discovery" > "$PKG/DEBIAN/conffiles"

SIZE=$(du -sk "$PKG" | cut -f1)
cat > "$PKG/DEBIAN/control" <<CONTROL
Package: iureti-discovery
Version: $VERSION
Architecture: $ARCH
Maintainer: Eduardo Llaguno <eduardo@llaguno.com>
Installed-Size: $SIZE
Depends: iputils-ping, iproute2, adduser, ca-certificates
Section: net
Priority: optional
Homepage: https://github.com/ellaguno/iureTI
Description: iureTI Discovery - sonda de inventario de TI para iurefficient
 Descubre equipos de la red (barrido, puertos, SNMP, mDNS, UPnP, NetBIOS),
 los clasifica y los envía al inventario de iurefficient. Corre como servicio
 (iureti-discovery.service) con interfaz web local en 127.0.0.1:8765.
CONTROL

mkdir -p "$OUT"
dpkg-deb --build --root-owner-group -Zxz "$PKG" "$OUT/iureti-discovery_${VERSION}_${ARCH}.deb" >/dev/null
(cd "$OUT" && sha256sum "iureti-discovery_${VERSION}_${ARCH}.deb" > "iureti-discovery_${VERSION}_${ARCH}.deb.sha256")
ls -lh "$OUT"/iureti-discovery_"${VERSION}"_"${ARCH}".deb
