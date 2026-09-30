# iureTI Discovery

Sonda de **autodescubrimiento de recursos de TI** para Linux que alimenta el módulo de
Inventario de **iurefficient**: PCs, laptops, servidores, switches, firewalls, impresoras,
access points y más.

> Estado: MVP en desarrollo. Ver [docs/](docs/README.md).

## Documentación

- [Visión y factibilidad](docs/01-vision-factibilidad.md)
- [Fuentes de descubrimiento](docs/02-fuentes-descubrimiento.md)
- [Arquitectura](docs/03-arquitectura.md)
- [Contrato de la API de ingesta](docs/04-api-ingesta.md)
- [Seguridad y operación](docs/05-seguridad.md)
- [Roadmap](docs/06-roadmap.md)

> ⚠️ Usa esta herramienta **solo en redes donde tengas autorización** expresa para hacerlo.

## Inicio rápido

Requiere Linux, Python 3.11+ y [uv](https://docs.astral.sh/uv/). No requiere root.

```bash
git clone https://github.com/ellaguno/iureTI.git && cd iureTI
uv sync
uv run iureti-discovery oui-update          # base de fabricantes por MAC (IEEE)
uv run iureti-discovery serve --open        # interfaz web en http://127.0.0.1:8765/
```

Desde la terminal:

```bash
uv run iureti-discovery networks                          # redes de este equipo
uv run iureti-discovery scan 192.168.1.0/24 --community public
uv run iureti-discovery export --format csv -o activos.csv # para Inventario › Importar
uv run iureti-discovery sync                               # envía a iurefficient (URL y token en la configuración)
```

La interfaz escucha solo en `127.0.0.1`. En un servidor sin escritorio, usa un túnel SSH
(`ssh -L 8765:127.0.0.1:8765 servidor`) en vez de exponerla en la red.

## Desarrollo

```bash
uv run pytest
```
