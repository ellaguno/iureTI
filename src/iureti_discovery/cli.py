"""Línea de comandos: iureti-discovery {serve,scan,networks,export,sync,oui-update}."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import webbrowser

from . import __version__, netutil, service
from .oui import OuiDatabase
from .store import Store
from .sync import DEVICE_TYPE_LABELS, SyncError, build_batch, to_import_csv


def cmd_serve(args) -> None:
    import uvicorn

    from .web.app import create_app

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"AVISO: la interfaz quedará expuesta en {args.host}:{args.port} sin autenticación. "
              "Usa un firewall o un túnel SSH (ver docs/05-seguridad.md).", file=sys.stderr)
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}/"
    print(f"iureTI Discovery {__version__} — {url}")
    if args.open:
        webbrowser.open(url)
    uvicorn.run(create_app(args.db), host=args.host, port=args.port, log_level="warning")


def cmd_networks(args) -> None:
    for n in netutil.local_networks():
        print(f"{n.network:<20} {n.interface:<18} {'(virtual)' if n.virtual else ''}")


def cmd_scan(args) -> None:
    store = Store(args.db)
    if args.community:
        creds = [{"name": f"cli-{i + 1}", "version": "2c", "community": c} for i, c in enumerate(args.community)]
        store.update_settings({"snmp_credentials": creds})
    scanner = service.make_scanner(store, args.targets, use_snmp=not args.no_snmp)

    async def run():
        task = asyncio.create_task(service.run_scan(store, scanner))
        while not task.done():
            p = scanner.progress
            if sys.stderr.isatty():
                print(f"\r{p.phase:<16} {p.done}/{p.total}  vivos: {p.alive}   ", end="", file=sys.stderr)
            await asyncio.sleep(0.5)
        if sys.stderr.isatty():
            print(file=sys.stderr)
        return task.result()

    try:
        summary = asyncio.run(run())
    except ValueError as exc:
        sys.exit(f"Error: {exc}")
    except KeyboardInterrupt:
        sys.exit("Cancelado")
    print(f"{summary['observed']} hosts vivos · {summary['new']} activos nuevos\n")
    ips_seen = set(netutil.expand_targets(args.targets))
    rows = [a for a in store.list_assets() if set(a.ips) & ips_seen]
    rows.sort(key=lambda a: tuple(int(x) for x in a.ips[0].split(".")))
    print(f"{'IP':<16}{'Tipo':<22}{'Nombre':<28}{'Fabricante':<28}{'Puertos'}")
    for a in rows:
        kind = f"{DEVICE_TYPE_LABELS.get(a.device_type, a.device_type)} {round(a.confidence * 100)}%"
        vendor = (a.vendor or "")[:26]
        print(f"{a.ips[0]:<16}{kind:<22}{(a.hostname or '')[:26]:<28}{vendor:<28}{' '.join(map(str, a.open_ports))}")


def cmd_export(args) -> None:
    store = Store(args.db)
    assets = store.list_assets()
    if args.format == "csv":
        data = to_import_csv(assets)
    else:
        scans = store.list_scans(1)
        data = json.dumps(build_batch(assets, store.get_settings(), scans[0] if scans else None),
                          ensure_ascii=False, indent=2).encode("utf-8")
    if args.output == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(args.output, "wb") as fh:
            fh.write(data)
        print(f"{len(assets)} activos exportados a {args.output}")


def cmd_sync(args) -> None:
    store = Store(args.db)
    try:
        r = service.sync_all(store, only_changed=args.changed)
    except SyncError as exc:
        sys.exit(f"Error: {exc}")
    print(f"Enviados {r['sent']} activos en {len(r['batches'])} lote(s): {r['results']}")


def cmd_oui_update(args) -> None:
    print(f"Base OUI actualizada: {OuiDatabase().update()} fabricantes")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="iureti-discovery", description="Sonda de autodescubrimiento de recursos de TI")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--db", help="Ruta de la base SQLite (por omisión ~/.local/share/iureti-discovery/iureti.db)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="Inicia la interfaz web local")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--open", action="store_true", help="Abre el navegador")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("networks", help="Muestra las redes de este equipo")
    p.set_defaults(func=cmd_networks)

    p = sub.add_parser("scan", help="Escanea rangos desde la terminal")
    p.add_argument("targets", nargs="+", help="CIDR, rango (10.0.0.1-50) o IP")
    p.add_argument("--community", action="append", help="Community SNMP v2c (se guarda en la configuración)")
    p.add_argument("--no-snmp", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("export", help="Exporta los activos")
    p.add_argument("--format", choices=["csv", "json"], default="csv",
                   help="csv = plantilla de Inventario › Importar; json = contrato de la API")
    p.add_argument("-o", "--output", default="-")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("sync", help="Envía los activos a iurefficient")
    p.add_argument("--changed", action="store_true", help="Solo los nuevos o con cambios desde el último envío")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("oui-update", help="Descarga la base de fabricantes (IEEE)")
    p.set_defaults(func=cmd_oui_update)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
