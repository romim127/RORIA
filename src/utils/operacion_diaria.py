import argparse
import datetime as dt
import re
from pathlib import Path

import pandas as pd

try:
    from src.utils.detection_report import generar_reporte_html
    from src.utils.kml_generator import generar_kml_preciso
    from src.utils.projections import ProjectionEngine
    from src.utils.skyeye_geo_pipeline import run_pipeline
except ModuleNotFoundError:
    from detection_report import generar_reporte_html
    from kml_generator import generar_kml_preciso
    from projections import ProjectionEngine
    from skyeye_geo_pipeline import run_pipeline


def _find_latest_csv(root: Path):
    csvs = [p for p in root.glob('*.csv') if p.is_file()]
    if not csvs:
        raise FileNotFoundError('No se encontraron CSV en la carpeta raiz.')
    return max(csvs, key=lambda p: p.stat().st_mtime)


def _load_csv(input_csv: Path):
    return pd.read_csv(input_csv, sep=None, engine='python', encoding='latin-1')


def _clean_columns(df):
    df.columns = [re.sub(r'^[\W_]+', '', str(c)).strip() for c in df.columns]
    return df


def _is_detection_report(df):
    cols = set(df.columns)
    return 'Source' in cols and 'Last Detected Location (Lat Lng)' in cols


def _is_trajectory_csv(df):
    cols = set(df.columns)
    return 'Location' in cols and 'Timestamp' in cols


def _extract_numbers(value):
    text = str(value).strip()
    return [float(x) for x in re.findall(r'[-+]?\d+(?:\.\d+)?', text)]


def _decode_location(value, proyector):
    nums = _extract_numbers(value)
    if len(nums) >= 2 and -90 <= nums[0] <= 90 and -180 <= nums[1] <= 180:
        return round(nums[0], 6), round(nums[1], 6), 'gps-directo'
    if len(nums) >= 1:
        lat, lon = proyector.calcular_coordenada_absoluta(nums[0])
        return lat, lon, 'offset-proyectado'
    return None, None, 'invalido'


def _decode_trajectory_csv(input_csv: Path, output_dir: Path):
    df = _load_csv(input_csv)
    df = _clean_columns(df)

    proyector = ProjectionEngine()

    decoded = df.copy()
    lats = []
    lons = []
    modos = []

    for loc in decoded['Location']:
        lat, lon, modo = _decode_location(loc, proyector)
        lats.append(lat)
        lons.append(lon)
        modos.append(modo)

    decoded['Latitud'] = lats
    decoded['Longitud'] = lons
    decoded['MetodoGeoref'] = modos

    stem = input_csv.stem.replace(' ', '_')
    out_csv = output_dir / f'{stem}_decodificado.csv'
    out_kml = output_dir / f'{stem}_trayectoria.kml'

    decoded.to_csv(out_csv, index=False, encoding='utf-8')
    generar_kml_preciso(str(input_csv), str(out_kml))

    return out_csv, out_kml, len(decoded)


def procesar_archivo(input_csv: Path, out_root: Path):
    df = _load_csv(input_csv)
    df = _clean_columns(df)

    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir = out_root / f'proceso_{stamp}'
    run_dir.mkdir(parents=True, exist_ok=True)

    if _is_detection_report(df):
        html_file = run_dir / 'reporte_detecciones.html'
        generar_reporte_html(str(input_csv), str(html_file))

        pipeline_dir = run_dir / 'georef'
        run_pipeline(
            input_csv=str(input_csv),
            output_dir=str(pipeline_dir),
            source='drone',
            model_filter=None,
            device_filter=None,
            date_filter=None,
        )

        print('Tipo detectado: Detection Report de SkyEye')
        print(f'Reporte HTML: {html_file}')
        print(f'KML trayectorias: {pipeline_dir / "trayectorias_drones.kml"}')
        print(f'KML ultimas posiciones: {pipeline_dir / "ultimas_posiciones_drones.kml"}')
        print(f'Reporte TXT: {pipeline_dir / "reporte_georeferenciacion.txt"}')
        return

    if _is_trajectory_csv(df):
        out_csv, out_kml, total = _decode_trajectory_csv(input_csv, run_dir)
        print('Tipo detectado: CSV de trayectoria')
        print(f'Filas procesadas: {total}')
        print(f'CSV decodificado: {out_csv}')
        print(f'KML trayectoria: {out_kml}')
        return

    print('No se reconocio el formato de CSV.')
    print('Columnas detectadas:')
    for c in df.columns:
        print(f'- {c}')


def main():
    parser = argparse.ArgumentParser(description='Proceso diario SkyEye: detecta CSV, georreferencia y exporta reportes.')
    parser.add_argument('--input', default=None, help='CSV a procesar. Si se omite, toma el CSV mas nuevo en raiz.')
    parser.add_argument('--outdir', default='salidas_diarias', help='Carpeta de salida para resultados')
    args = parser.parse_args()

    root = Path('.').resolve()
    input_csv = Path(args.input).resolve() if args.input else _find_latest_csv(root)
    out_root = Path(args.outdir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    print(f'CSV seleccionado: {input_csv}')
    procesar_archivo(input_csv, out_root)


if __name__ == '__main__':
    main()
