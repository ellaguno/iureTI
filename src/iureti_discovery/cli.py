"""Línea de comandos: iureti-discovery {serve,enroll,status,schedule,networks,scan,export,sync,enrich,consolidate,oui-update}."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import webbrowser

from . import __version__, enrich, netutil, service
from .oui import OuiDatabase
from .store import Store
from .sync import DEVICE_TYPE_LABELS, SyncError, build_batch, to_import_csv


def ui_url(host: str, port: int) -> tuple[str, bool]:
    """URL de la interfaz web y si queda expuesta fuera de este equipo."""
    return f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/", host not in ("127.0.0.1", "localhost", "::1")


def cmd_serve(args) -> None:
    import logging

    import uvicorn

    from .web.app import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    app = create_app(args.db, agent=args.agent, bind_host=args.host, port=args.port)
    url, exposed = ui_url(args.host, args.port)
    if exposed:
        token = Store(args.db).get_settings().get("ui_token", "")
        print(f"AVISO: la interfaz queda EXPUESTA en {args.host}:{args.port}. Mejor un túnel SSH "
              "(ssh -L 8765:127.0.0.1:8765 …) que abrirla en la red (ver docs/05-seguridad.md).", file=sys.stderr)
        print(f"Para entrar hace falta este token (ábrela con ?token=…):\n  {url}?token={token}")
    else:
        print(f"iureTI Discovery {__version__} — {url}")
    if args.open:
        webbrowser.open(url + (f"?token={Store(args.db).get_settings().get('ui_token','')}" if exposed else ""))
    if args.agent:
        print("Modo servicio: heartbeat con iurefficient y escaneos programados activos")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


def cmd_enroll(args) -> None:
    from .agent import Agent
    from .runtime import Runtime

    # El token en la línea de comandos es visible en `ps`: se prefiere el entorno o la entrada estándar.
    token = args.token or os.environ.get("IURETI_TOKEN", "")
    if token == "-" or (not token and not sys.stdin.isatty()):
        token = sys.stdin.readline().strip()
    if not token:
        sys.exit("Falta el token de sonda: --token, la variable IURETI_TOKEN, o por entrada estándar")
    if not args.url.lower().startswith(("https://", "http://")):
        sys.exit("La URL debe empezar por https:// (o http:// a una dirección local)")

    store = Store(args.db)
    values = {"api_url": args.url.rstrip("/"), "api_token": token}  # «gestionada» al recibir config
    if args.name:
        values["probe_id"] = args.name
    if args.site:
        values["site"] = args.site
    store.update_settings(values)
    print(f"Sonda configurada para {values['api_url']}")

    async def check():
        agent = Agent(Runtime(store))
        await agent.heartbeat()
        return agent.state

    state = asyncio.run(check())
    if state["connected"]:
        print("✓ Conectada: iurefficient recibió el primer heartbeat")
    else:
        print(f"⚠ {state['error']}")
        print("  La configuración quedó guardada; el servicio reintentará cada pocos minutos.")


def cmd_status(args) -> None:
    store = Store(args.db)
    s = store.get_settings()
    scans = store.list_scans(1)
    assets = store.list_assets()
    print(f"iureTI Discovery {__version__}")
    url, exposed = ui_url(os.environ.get("IURETI_HOST") or "127.0.0.1", int(os.environ.get("IURETI_PORT") or 8765))
    if not exposed:
        url += "  (solo desde este equipo)"
    elif s.get("ui_token"):
        url += f"?token={s['ui_token']}"
    else:
        url += "  (el token se genera al arrancar el servicio)"
    print(f"  Interfaz web:   {url}")
    print(f"  Base de datos:  {store.path}")
    print(f"  Sonda:          {s.get('probe_id') or '(hostname)'}  sitio: {s.get('site') or '-'}")
    print(f"  iurefficient:   {s.get('api_url') or '(no configurado)'}{'  [gestionada]' if s.get('managed') else ''}")
    interval = int(s.get("schedule_interval_minutes") or 0)
    sched = f"cada {interval} min" + (f" entre {s['schedule_window']}" if s.get("schedule_window") else "") if interval else "desactivada"
    print(f"  Programación:   {sched}  rangos: {', '.join(s.get('targets') or []) or '-'}")
    print(f"  Activos:        {len(assets)}")
    if scans:
        last = scans[0]
        print(f"  Último escaneo: {last['started_at']}  {last['phase']}  vivos: {last['alive']}  nuevos: {last['new_assets']}"
              + (f"  error: {last['error']}" if last.get("error") else ""))


def cmd_schedule(args) -> None:
    store = Store(args.db)
    values = {}
    if args.every is not None:
        units = {"m": 1, "h": 60, "d": 1440}
        try:
            values["schedule_interval_minutes"] = 0 if args.every in ("0", "off") else int(args.every[:-1]) * units[args.every[-1]]
        except (KeyError, ValueError):
            sys.exit("Usa --every 30m, 6h, 1d u off")
    if args.window is not None:
        from .agent import parse_window
        if args.window and parse_window(args.window) is None:
            sys.exit("Ventana inválida: usa HH:MM-HH:MM")
        values["schedule_window"] = args.window
    if args.targets:
        netutil.expand_targets(args.targets)
        values["targets"] = args.targets
    if args.auto_sync is not None:
        values["auto_sync"] = args.auto_sync == "on"
    if args.auto_enrich is not None:
        values["auto_enrich"] = args.auto_enrich == "on"
    store.update_settings(values)
    cmd_status(args)


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
        if v := a.attributes.get("virtual"):
            kind += f" [{'VM' if v.get('kind') == 'vm' else 'contenedor'}{' en ' + (v.get('host_name') or v.get('host_ip')) if v.get('host_name') or v.get('host_ip') else ''}]"
        elif a.attributes.get("guests"):
            kind += f" [aloja {len(a.attributes['guests'])}]"
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


def cmd_enrich(args) -> None:
    store = Store(args.db)
    if args.enable:
        store.update_settings({"enrich_enabled": True})
    if args.provider:
        store.update_settings({"enrich_provider": args.provider})
    if args.model:
        provider = store.get_settings()["enrich_provider"]
        store.update_settings({f"{provider}_model": args.model})
    ids = service.enrich_candidates(store, only_missing=not args.all)
    if not ids:
        print("No hay activos pendientes con datos de producto para buscar.")
        return
    for asset_id in ids:
        asset = store.get_asset(asset_id)
        label = f"{(asset.ips or [''])[0]:<16}{asset.vendor[:24]:<26}{asset.model[:30]}"
        try:
            r = service.enrich_asset(store, asset_id, force=args.all)
        except enrich.EnrichError as exc:
            print(f"{label}  ✗ {exc}")
            if any(w in str(exc) for w in ("Clave", "clave", "desactivada", "créditos")):
                sys.exit(1)
            continue
        e = r["asset"]["attributes"]["enrichment"]
        found = e.get("product_name") if e.get("identified") else "no identificado"
        extra = " (caché)" if r["cached"] else (f" ${e['cost_usd']:.4f}" if e.get("cost_usd") is not None else "")
        print(f"{label}  → {found} [{e.get('confidence')}]{' 📷' if e.get('image_file') else ''}{extra}")


def cmd_consolidate(args) -> None:
    """Fusiona los duplicados que ya hubiera en la base (también ocurre solo en cada escaneo)."""
    store = Store(args.db)
    before = len(store.list_assets())
    merged = service.consolidate(store)
    print(f"{merged} duplicado(s) fusionado(s): {before} → {before - merged} activos")


def cmd_oui_update(args) -> None:
    from .oui import OuiUpdateError

    try:
        print(f"Base OUI actualizada: {OuiDatabase().update()} fabricantes")
    except OuiUpdateError as exc:
        sys.exit(str(exc))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iureti-discovery", description="Sonda de autodescubrimiento de recursos de TI")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--db", help="Ruta de la base SQLite (por omisión ~/.local/share/iureti-discovery/iureti.db)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="Inicia la interfaz web local")
    # «or»: el wrapper del .deb puede pasar IURETI_HOST/IURETI_PORT vacíos cuando /etc/default no los fija
    p.add_argument("--host", default=os.environ.get("IURETI_HOST") or "127.0.0.1")
    p.add_argument("--port", type=int, default=int(os.environ.get("IURETI_PORT") or 8765))
    p.add_argument("--open", action="store_true", help="Abre el navegador")
    p.add_argument("--agent", action="store_true", help="Modo servicio: heartbeat con iurefficient y escaneos programados")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("enroll", help="Registra la sonda en iurefficient (URL + token de sonda)")
    p.add_argument("--url", required=True, help="URL de iurefficient, p.ej. https://cliente.iurefficient.com")
    p.add_argument("--token", help="Token de sonda (iurprobe_…). Mejor por la variable IURETI_TOKEN "
                   "o por entrada estándar (--token -): la línea de comandos es visible en `ps`")
    p.add_argument("--name", help="Identificador de la sonda (por omisión, el hostname)")
    p.add_argument("--site", help="Sitio / sucursal")
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("status", help="Estado de la sonda")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("schedule", help="Escaneos programados (modo servicio)")
    p.add_argument("--every", help="Intervalo: 30m, 6h, 1d u off")
    p.add_argument("--window", help="Ventana horaria local HH:MM-HH:MM ('' = cualquier hora)")
    p.add_argument("--targets", nargs="+", help="Rangos a escanear")
    p.add_argument("--auto-sync", choices=["on", "off"], help="Enviar a iurefficient tras cada escaneo")
    p.add_argument("--auto-enrich", choices=["on", "off"], help="Buscar en internet los productos nuevos")
    p.set_defaults(func=cmd_schedule)

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

    p = sub.add_parser("enrich", help="Identifica productos en internet (Claude + búsqueda web)")
    p.add_argument("--all", action="store_true", help="Vuelve a buscar también los ya identificados")
    p.add_argument("--enable", action="store_true", help="Activa la búsqueda en internet en la configuración")
    p.add_argument("--provider", choices=["openrouter", "anthropic"], help="Proveedor (se guarda en la configuración)")
    p.add_argument("--model", help="Modelo del proveedor (se guarda), p.ej. google/gemini-3.1-flash-lite")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("consolidate", help="Fusiona activos duplicados (el mismo equipo visto en varios escaneos)")
    p.set_defaults(func=cmd_consolidate)

    p = sub.add_parser("oui-update", help="Descarga la base de fabricantes (IEEE)")
    p.set_defaults(func=cmd_oui_update)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
