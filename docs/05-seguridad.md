# 05 — Seguridad y operación

## Principios

1. **Solo con autorización.** Cada despliegue requiere autorización escrita del cliente
   que indique rangos, horarios y la IP de la sonda. Escanear redes ajenas sin permiso
   puede ser ilegal.
2. **Solo lectura.** Credenciales SNMP read-only, cuenta LDAP de lectura, cuentas WinRM/SSH
   sin privilegios de escritura. La sonda nunca modifica configuraciones.
3. **Mínima huella.** Límite de concurrencia y velocidad configurables; preferir fuentes
   pasivas o con credencial (SNMP, AD) sobre barridos masivos.
4. **Las credenciales no salen de la sonda.** Se guardan cifradas localmente y nunca se
   envían a iurefficient.

## Checklist de despliegue con el cliente

- [ ] Autorización firmada (rangos, horario, contacto de seguridad)
- [ ] IP / hostname de la sonda registrados en IDS/EDR/SIEM como escáner autorizado
- [ ] Reglas de firewall: sonda → redes objetivo (ICMP, TCP puertos de huella, UDP 161)
- [ ] Community SNMPv2c o usuario SNMPv3 de solo lectura, con ACL limitada a la IP de la sonda
- [ ] (v2) Cuenta de servicio LDAP de solo lectura
- [ ] (v3) WinRM habilitado por GPO para la cuenta de inventario
- [ ] Token de sonda emitido en iurefficient

## Protección de la sonda

- La UI web escucha por defecto solo en `127.0.0.1`. Para exponerla en la red se debe
  configurar explícitamente `--host 0.0.0.0` y **debe** protegerse (v2: usuario/contraseña
  y TLS; mientras tanto, usar túnel SSH).
- Base de datos SQLite con permisos `600`.
- Secretos: v2 usará el keyring del sistema (Secret Service) o un archivo cifrado con
  clave derivada.
- Registro (log) de cada escaneo: quién lo lanzó, rangos, fuentes, duración.

## Identificación por internet (opcional, desactivada por omisión)

Se activa en Configuración › Búsqueda en internet y requiere una clave de **OpenRouter** (por omisión) o de
**Anthropic**. Con OpenRouter los datos pasan por OpenRouter y por el proveedor del modelo elegido; la sonda
pide `provider.data_collection: "deny"` para usar solo proveedores que no guardan ni entrenan con los datos.

**Qué se envía** (función `enrich.product_facts`, con prueba automática que lo verifica): tipo probable,
fabricante, modelo, SO/firmware, sysObjectID y sysDescr de SNMP, fabricante/modelo/tipo UPnP, título y
servidor de la página web del equipo con sus candidatos de modelo, servicios mDNS y su TXT de modelo, el
nombre anunciado **solo si parece un producto** («Pixel 9 Pro»), familia de SO por TTL y puertos abiertos.

**Qué nunca se envía**: IPs, MACs, hostnames, números de serie, `sysLocation`/`sysContact`, nombres que
pone el usuario (`friendlyName`, «iPhone de Juan»), ni nada del cliente o de la red.

Además, como última barrera, antes de enviar se borran de **todos** los campos de texto el hostname, el
sysName, el nombre NetBIOS/mDNS, las series, las IPs y las MACs del equipo (p. ej. el `sysDescr` de Linux
incluye el hostname: «Linux srv-contabilidad 5.15…» → «Linux [equipo] 5.15…»).

**Protecciones**:
- La sonda solo descarga imágenes/páginas de URLs **públicas** (resuelve el host y rechaza IPs privadas,
  loopback y link-local) para que una URL devuelta por la búsqueda no la haga consultar la red interna.
- Imágenes: solo `image/jpeg|png|webp|gif`, máximo 5 MB, guardadas en `~/.cache/iureti-discovery/images`.
- Las claves de API se guardan en la BD local (permisos 600) y se enmascaran en la interfaz; también se
  pueden dar por variable de entorno (`OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`).
- Con Anthropic, modelo por omisión `claude-opus-5-5` con `fallbacks: "default"`: si el modelo declina una
  consulta, la API la reintenta en el modelo de respaldo recomendado.

## Consideraciones legales / privacidad

- Hostnames y usuarios de sesión pueden ser datos personales: tratarlos conforme al aviso
  de privacidad del cliente.
- La sonda no captura tráfico ni contenido de comunicaciones.
