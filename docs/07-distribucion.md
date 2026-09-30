# 07 — Distribución e instalación de sondas

## Dónde va la sonda

La sonda descubre por ARP, mDNS, SSDP y barridos: **tiene que estar dentro de la red del cliente**.
Una sonda junto a una instancia de iurefficient en la nube solo vería la red interna de la nube.

| iurefficient del cliente | Sonda |
|---|---|
| En la nube (GCP) | Una o más sondas en la oficina del cliente (servidor Linux, VM o Raspberry Pi), una por sitio o VLAN |
| On‑premise (Docker Compose en su servidor) | La sonda puede ir en el mismo `docker-compose.yml` (perfil `sonda`, ver abajo) |

La sonda **solo hace conexiones salientes** HTTPS a iurefficient (heartbeat + envío de lotes); no abre
puertos. Su interfaz web escucha únicamente en `127.0.0.1:8765`.

## Flujo recomendado

1. En iurefficient: *Inventario › Sondas › Agregar sonda* (nombre y sitio) → genera el token
   `iurprobe_…` y el comando de instalación. *(Pendiente del lado de iurefficient: tramos D1 + gestión de
   sondas, contrato en [04](04-api-ingesta.md).)*
2. En el equipo del cliente se pega el comando:
   ```bash
   curl -fsSL https://github.com/ellaguno/iureTI/releases/latest/download/install.sh | sudo sh -s -- \
     --url https://cliente.iurefficient.com --token iurprobe_xxxxx --site "Matriz" --name sonda-matriz
   ```
3. La sonda aparece «conectada» en iurefficient; los rangos y la programación se definen allá y le llegan
   en el siguiente heartbeat (cada 5 minutos).

Mientras iurefficient no tenga la gestión de sondas, se configura en la propia sonda:
```bash
sudo iureti-discovery schedule --every 1d --window 01:00-05:00 --targets 192.168.1.0/24
sudo iureti-discovery status
```

## Formatos

### 1. Paquete `.deb` + systemd (principal)
Debian 12, Ubuntu 22.04/24.04, Raspberry Pi OS (64 bits); `amd64` y `arm64`.

- Trae **su propio Python 3.12** en `/opt/iureti` (no depende del Python del sistema). ~28 MB.
- Crea el usuario de sistema `iureti` (sin shell, sin root) y el servicio `iureti-discovery.service`
  (`serve --agent`), habilitado al arranque.
- Datos en `/var/lib/iureti/iureti.db` (permisos `600`), caché (OUI, imágenes) en `/var/cache/iureti`.
- Ajustes del servicio en `/etc/default/iureti-discovery` (host/puerto de la interfaz, claves de IA).
- `iureti-discovery` en `/usr/bin` usa la base del servicio; con `sudo` corre como `iureti`.
- Endurecido con systemd: `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, y como único
  privilegio `CAP_NET_RAW` (para `ping` en distribuciones que lo necesitan).
- `apt purge iureti-discovery` borra inventario local, configuración (incluye secretos) y el usuario.

`install.sh` detecta distribución y arquitectura, descarga el `.deb` del último release de GitHub,
**verifica su SHA-256**, lo instala con `apt` (resuelve dependencias), registra la sonda si se dan
`--url/--token` y reinicia el servicio. Volver a correrlo **actualiza**; es idempotente.

### 2. Imagen Docker (`ghcr.io/ellaguno/iureti`)
Multi‑arquitectura (`amd64`, `arm64`). Requiere **red del host** para ver la LAN; solo en Linux
(Docker Desktop en Windows/Mac no da acceso real a la red de la oficina).

```bash
docker run -d --name iureti --network host --restart unless-stopped \
  -v iureti-data:/data ghcr.io/ellaguno/iureti:latest
docker exec iureti iureti-discovery enroll --url https://cliente.iurefficient.com --token iurprobe_xxxxx
```

Corre como usuario sin privilegios (uid 10001); datos en el volumen `/data`.

**Junto a iurefficient on‑premise** — servicio adicional en el `docker-compose.yml` de la instancia:
```yaml
  sonda:
    image: ghcr.io/ellaguno/iureti:latest
    profiles: ["sonda"]          # docker compose --profile sonda up -d
    network_mode: host           # imprescindible: ARP, mDNS y SSDP
    restart: unless-stopped
    volumes:
      - sonda_data:/data
    environment:
      IURETI_PORT: "8765"
# y en volumes:  sonda_data:
```
Se registra con `docker compose exec sonda iureti-discovery enroll --url http://127.0.0.1:<puerto-backend> --token …`.

### 3. Appliance (siguiente paso)
Para clientes sin Linux: imagen para **Raspberry Pi 5** (arm64) y **OVA/VHDX** (VMware/Proxmox/Hyper‑V)
con la sonda preinstalada; al primer arranque se abre la interfaz local para pegar la URL y el token.
Se construye sobre el mismo `.deb`.

### 4. Desarrollo / técnicos
```bash
uv tool install git+https://github.com/ellaguno/iureTI   # o: git clone … && uv sync
```

## Publicar una versión

1. Subir `version` en `pyproject.toml` y `src/iureti_discovery/__init__.py`.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. GitHub Actions (`release.yml`): pruebas → `.deb` amd64 y arm64 (construidos en `debian:12` y probados
   en Ubuntu 22.04/24.04 limpios) → imagen multi‑arquitectura en ghcr.io → Release con los `.deb`,
   sus `.sha256`, `SHA256SUMS` e `install.sh`.

Construir el `.deb` localmente:
```bash
docker run --rm -v "$PWD":/src -w /src debian:12 bash packaging/build-deb.sh   # → dist/
```

## Actualizaciones

- `.deb`: volver a correr `install.sh` (o `--upgrade`). La interfaz local avisa cuando iurefficient
  reporta una `latest_version` mayor en el heartbeat.
- Docker: `docker pull ghcr.io/ellaguno/iureti:latest && docker restart iureti` (o Watchtower).
- Pendiente: repositorio apt firmado (`apt upgrade` automático con `unattended-upgrades`).

## Windows

La sonda depende de Linux (`ip`, `/proc/net/arp`, `ping`). WSL2 no sirve (NAT: no ve la red de la
oficina). Para clientes solo‑Windows: appliance (Raspberry Pi o VM pequeña en Hyper‑V).
