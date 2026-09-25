# Backup Linux - Detection of Signals

Este backup es para la carpeta persistente de datos de la plataforma. No guarda el backup en carpetas compartidas por defecto.

## Carpeta recomendada de datos

```bash
/var/lib/detection-signals
```

La app debe leer esa ruta con la variable:

```bash
SKYEYE_DATA_DIR=/var/lib/detection-signals
```

## Carpeta recomendada de backups

```bash
/var/backups/detection-signals
```

Debe tener permisos restringidos.

## Backup recomendado

Ejecutar desde la raiz del proyecto:

```bash
sudo bash scripts/linux_backup_detection_signals.sh --stop-service
```

Esto:

- detiene el servicio `detection-signals` si estaba activo,
- comprime la carpeta de datos,
- genera archivo `.sha256`,
- vuelve a iniciar el servicio,
- conserva backups locales por 30 dias.

## Backup con rutas explicitas

```bash
sudo bash scripts/linux_backup_detection_signals.sh \
  --data-dir /var/lib/detection-signals \
  --backup-dir /var/backups/detection-signals \
  --service detection-signals \
  --retention-days 30 \
  --stop-service
```

## Verificar hash

```bash
cd /var/backups/detection-signals
sha256sum -c detection_signals_data_HOST_FECHA.tar.gz.sha256
```

## Nota de seguridad

La carpeta compartida del Dpto Tec puede usarse como copia secundaria solo si Infraestructura autoriza el resguardo y define permisos/cifrado.
La base de datos y los informes contienen informacion sensible, por lo que el backup principal debe quedar local y protegido en el servidor de la app.
