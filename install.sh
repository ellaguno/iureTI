#!/bin/sh
# Instalador de la sonda iureTI Discovery (Debian / Ubuntu / Raspberry Pi OS; amd64 y arm64).
#
#   curl -fsSL https://github.com/ellaguno/iureTI/releases/latest/download/install.sh | sudo sh -s -- \
#     --url https://cliente.iurefficient.com --token iurprobe_xxxxx --site "Matriz"
#
# Opciones:
#   --url URL        URL de iurefficient (junto con --token registra la sonda)
#   --token TOKEN    Token de sonda (Inventario › Sondas › Agregar sonda)
#   --name NOMBRE    Identificador de la sonda (por omisión, el hostname)
#   --site SITIO     Sitio o sucursal
#   --version X.Y.Z  Versión a instalar (por omisión, la última)
#   --upgrade        Solo actualiza el paquete (conserva configuración e inventario)
# Volver a correr el instalador actualiza a la última versión.
set -eu

REPO="ellaguno/iureTI"
# El token puede venir por la variable IURETI_TOKEN (no queda en el historial ni en `ps`).
URL="" TOKEN="${IURETI_TOKEN:-}" NAME="" SITE="" PKG_VERSION="" UPGRADE=0

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo ">> $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --site) SITE="$2"; shift 2 ;;
        --version) PKG_VERSION="${2#v}"; shift 2 ;;
        --upgrade) UPGRADE=1; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) die "opción desconocida: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "ejecuta como root (sudo sh -s -- ...)"
[ -n "$URL" ] && [ -z "$TOKEN" ] && die "--url requiere --token"
[ -n "$TOKEN" ] && [ -z "$URL" ] && die "--token requiere --url"

# --- sistema soportado -------------------------------------------------------
[ -r /etc/os-release ] || die "no se reconoce el sistema operativo"
# En un subshell: os-release define VERSION, ID, etc. y no debe pisar nuestras variables
OS_IDS=$(. /etc/os-release; echo " ${ID:-} ${ID_LIKE:-} ")
OS_NAME=$(. /etc/os-release; echo "${PRETTY_NAME:-?}")
case "$OS_IDS" in
    *" debian "*|*" ubuntu "*) ;;
    *) die "sistema no soportado ($OS_NAME). Usa la imagen Docker:
  docker run -d --name iureti --network host --restart unless-stopped -v iureti-data:/data ghcr.io/ellaguno/iureti:latest" ;;
esac
command -v systemctl >/dev/null || die "se requiere systemd"
ARCH=$(dpkg --print-architecture)
case "$ARCH" in amd64|arm64) ;; *) die "arquitectura no soportada: $ARCH (amd64 o arm64)" ;; esac

command -v curl >/dev/null || { info "instalando curl"; apt-get update -qq && apt-get install -y -qq curl ca-certificates; }

# --- versión -------------------------------------------------------------------
if [ -z "$PKG_VERSION" ]; then
    PKG_VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
    [ -n "$PKG_VERSION" ] || die "no se pudo consultar la última versión en GitHub"
fi
INSTALLED=$(dpkg-query -W -f='${Version}' iureti-discovery 2>/dev/null || true)
DEB="iureti-discovery_${PKG_VERSION}_${ARCH}.deb"
BASE="${IURETI_RELEASE_BASE:-https://github.com/$REPO/releases/download/v${PKG_VERSION}}"  # override: pruebas / espejo

# --- descarga, verificación e instalación -------------------------------------
if [ "$INSTALLED" = "$PKG_VERSION" ]; then
    info "iureti-discovery $PKG_VERSION ya está instalado"
else
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    info "descargando $DEB"
    curl -fsSL -o "$TMP/$DEB" "$BASE/$DEB" || die "no existe $BASE/$DEB"
    curl -fsSL -o "$TMP/$DEB.sha256" "$BASE/$DEB.sha256" || die "no se pudo descargar la suma de verificación"
    (cd "$TMP" && sha256sum -c "$DEB.sha256" >/dev/null) || die "la suma de verificación no coincide"
    info "instalando ${INSTALLED:+(actualiza $INSTALLED → )}$PKG_VERSION"
    chmod 0644 "$TMP/$DEB"  # apt lo lee como usuario _apt
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$TMP/$DEB" >/dev/null
fi

# --- registro en iurefficient --------------------------------------------------
if [ "$UPGRADE" = 0 ] && [ -n "$URL" ]; then
    info "registrando la sonda en $URL"
    # El token va por la entrada estándar (--token -), no por argv: no aparece en `ps`.
    set -- enroll --url "$URL" --token -
    [ -n "$NAME" ] && set -- "$@" --name "$NAME"
    [ -n "$SITE" ] && set -- "$@" --site "$SITE"
    printf '%s\n' "$TOKEN" | iureti-discovery "$@" || true
fi

systemctl restart iureti-discovery.service
sleep 2
if systemctl is-active --quiet iureti-discovery.service; then
    info "servicio iureti-discovery activo"
else
    echo "El servicio no arrancó; revisa: journalctl -u iureti-discovery -n 50" >&2
fi

cat <<MSG

iureTI Discovery $PKG_VERSION instalado.
  Estado:      sudo iureti-discovery status
  Bitácora:    journalctl -u iureti-discovery -f
  Interfaz:    http://127.0.0.1:8765/  (desde otro equipo: ssh -L 8765:127.0.0.1:8765 $(hostname))
  Programar:   sudo iureti-discovery schedule --every 1d --window 01:00-05:00 --targets 192.168.1.0/24
  Actualizar:  vuelve a correr este instalador (o con --upgrade)
  Desinstalar: sudo apt purge iureti-discovery   (borra inventario local y configuración)

Escanea solo redes para las que tengas autorización expresa.
MSG
