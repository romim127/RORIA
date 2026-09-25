# NEXA Digital Forensic Suite v0.5.1 — Ministerio FIXED

Esta versión corrige el fallo por el cual se generaban únicamente los archivos
de timeline (`CSV` y `JSON`) pero no el informe técnico.

## Correcciones principales

- Todas las rutas se resuelven desde la carpeta real de `nexa.py`.
- El motor RF se ejecuta con rutas absolutas.
- La salida y los errores del motor se guardan en:
  `rf_engine_console.log`.
- NEXA solamente muestra **DONE** cuando el archivo correspondiente existe.
- Si falla el Word, la pantalla final informa claramente el error.
- Los módulos futuros vuelven a mostrar `COMING SOON`.
- El nombre del informe dejó de estar fijado a UNCUYO.

## Instalación

```powershell
python -m pip install rich pandas matplotlib python-docx
```

## Preparación

Copiar dentro de `input`:

```text
history*.csv
networkcfg*.csv
```

## Ejecución

```powershell
cd "C:\NEXA_Digital_Forensic_Suite_v0_5_1_MINISTERIO_FIXED"
python .\nexa.py
```

## PDF

El informe Word se genera con Python. Para conversión automática a PDF,
LibreOffice debe estar instalado y su ejecutable `soffice` disponible.

Aunque no se genere PDF, el DOCX debe generarse. Si no se genera, revisar:

```text
output\<CASO>\rf_engine_console.log
```
