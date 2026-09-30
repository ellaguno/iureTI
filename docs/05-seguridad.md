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

## Consideraciones legales / privacidad

- Hostnames y usuarios de sesión pueden ser datos personales: tratarlos conforme al aviso
  de privacidad del cliente.
- La sonda no captura tráfico ni contenido de comunicaciones.
