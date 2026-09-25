import argparse
import datetime as dt
import html
import re
from pathlib import Path

import pandas as pd


def _clean_columns(df):
    df.columns = [re.sub(r'^[\W_]+', '', str(c)).strip() for c in df.columns]
    return df


def _normalize_model(value):
    if pd.isna(value):
        return 'Unknown Model'
    text = str(value).strip()
    text = text.replace('DJI â€”', 'DJI -').replace('DJI —', 'DJI -')
    text = re.sub(r'[^\x20-\x7E]+', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip() or 'Unknown Model'


def _parse_latlon(value):
    text = str(value).strip()
    nums = re.findall(r'[-+]?\d+(?:\.\d+)?', text)
    if len(nums) < 2:
        return None
    lat = float(nums[0])
    lon = float(nums[1])
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return round(lat, 6), round(lon, 6)


def _choose_coord(row):
    c1 = _parse_latlon(row.get('Last Detected Location (Lat Lng)', ''))
    if c1 is not None:
        return c1
    return _parse_latlon(row.get('Nearest Location [Lat Lng]', ''))


def _kml_color(i):
    palette = [
        'ff1f77b4',
        'ffff7f0e',
        'ff2ca02c',
        'ffd62728',
        'ff9467bd',
        'ff8c564b',
        'ffe377c2',
        'ff7f7f7f',
        'ffbcbd22',
        'ff17becf',
    ]
    return palette[i % len(palette)]


def _escape(value):
    return html.escape(str(value))


def _coord_text(row):
    return f"{round(float(row['lat']), 6)}, {round(float(row['lon']), 6)}"


def _apply_filters(df, source='drone', model_filter=None, device_filter=None, date_filter=None):
    data = df.copy()

    if source:
        data = data[data['Source'] == source.lower()]

    if model_filter:
        mf = model_filter.lower().strip()
        data = data[data['Model'].str.lower().str.contains(mf, na=False)]

    if device_filter:
        data = data[data['Device ID'].astype(str).str.strip() == device_filter.strip()]

    if date_filter:
        normalized = date_filter.replace('-', '.')
        data = data[data['Detect Time'].astype(str).str.startswith(normalized)]

    return data


def _preprocess(input_csv):
    df = pd.read_csv(input_csv, sep=None, engine='python', encoding='latin-1')
    df = _clean_columns(df)

    required = ['Source', 'Model', 'Detect Time', 'Device ID']
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f'CSV invalido. Faltan columnas obligatorias: {missing}')

    df['Source'] = df['Source'].fillna('').astype(str).str.strip().str.lower()
    df['Model'] = df['Model'].apply(_normalize_model)
    df['Device ID'] = df['Device ID'].fillna('').astype(str).str.strip()
    df['Detect DT'] = pd.to_datetime(df['Detect Time'], format='%Y.%m.%d %H:%M:%S', errors='coerce')
    df['Fecha'] = df['Detect DT'].dt.strftime('%Y-%m-%d')

    coords = df.apply(_choose_coord, axis=1)
    df['lat'] = coords.apply(lambda c: c[0] if c else None)
    df['lon'] = coords.apply(lambda c: c[1] if c else None)
    df['has_coord'] = df['lat'].notna() & df['lon'].notna()

    return df


def _drone_key(row):
    device = str(row.get('Device ID', '')).strip()
    model = str(row.get('Model', 'Unknown Model')).strip()
    return device if device else model


def _write_tracks_kml(df_points, out_file):
    grouped = []
    for key, group in df_points.groupby('Drone Key', dropna=False):
        g = group.sort_values('Detect DT')
        if len(g) < 1:
            continue
        grouped.append((str(key), g))

    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<kml xmlns="http://www.opengis.net/kml/2.2">', '<Document>', '<name>Trayectorias SkyEye</name>']

    for i, (key, g) in enumerate(grouped):
        style_id = f'style_{i}'
        color = _kml_color(i)
        lines.append(f'<Style id="{style_id}">')
        lines.append('<LineStyle>')
        lines.append(f'<color>{color}</color>')
        lines.append('<width>3</width>')
        lines.append('</LineStyle>')
        lines.append('<IconStyle>')
        lines.append(f'<color>{color}</color>')
        lines.append('<scale>1.1</scale>')
        lines.append('</IconStyle>')
        lines.append('</Style>')

        model = _escape(g['Model'].iloc[-1])
        last_time = _escape(g['Detect Time'].iloc[-1])

        lines.append('<Placemark>')
        lines.append(f'<name>{_escape(key)} | {model}</name>')
        lines.append(f'<styleUrl>#{style_id}</styleUrl>')
        lines.append(
            '<description><![CDATA['
            f"<b>Drone Key:</b> {_escape(key)}<br/>"
            f"<b>Modelo:</b> {model}<br/>"
            f"<b>Device ID:</b> {_escape(g['Device ID'].iloc[-1])}<br/>"
            f"<b>Source:</b> {_escape(g['Source'].iloc[-1])}<br/>"
            f"<b>Puntos:</b> {len(g)}<br/>"
            f"<b>Inicio:</b> {_escape(g['Detect Time'].iloc[0])}<br/>"
            f"<b>Fin:</b> {last_time}"
            ']]></description>'
        )
        lines.append('<LineString><tessellate>1</tessellate><coordinates>')
        for _, row in g.iterrows():
            lines.append(f'{row["lon"]},{row["lat"]},0')
        lines.append('</coordinates></LineString>')
        lines.append('</Placemark>')

        first = g.iloc[0]
        last = g.iloc[-1]
        lines.append('<Placemark>')
        lines.append(f'<name>INICIO { _escape(key) }</name>')
        lines.append(
            '<description><![CDATA['
            f"<b>Modelo:</b> {model}<br/>"
            f"<b>Device ID:</b> {_escape(first['Device ID'])}<br/>"
            f"<b>Source:</b> {_escape(first['Source'])}<br/>"
            f"<b>Detect Time:</b> {_escape(first['Detect Time'])}<br/>"
            f"<b>Tag:</b> {_escape(first.get('tag', ''))}<br/>"
            f"<b>Frecuencia:</b> {_escape(first.get('Frequency', ''))}<br/>"
            f"<b>Coordenadas:</b> {_coord_text(first)}"
            ']]></description>'
        )
        lines.append(f'<styleUrl>#{style_id}</styleUrl>')
        lines.append(f'<Point><coordinates>{first["lon"]},{first["lat"]},0</coordinates></Point>')
        lines.append('</Placemark>')

        lines.append('<Placemark>')
        lines.append(f'<name>FIN { _escape(key) }</name>')
        lines.append(
            '<description><![CDATA['
            f"<b>Modelo:</b> {model}<br/>"
            f"<b>Device ID:</b> {_escape(last['Device ID'])}<br/>"
            f"<b>Source:</b> {_escape(last['Source'])}<br/>"
            f"<b>Ultima deteccion:</b> {last_time}<br/>"
            f"<b>Tag:</b> {_escape(last.get('tag', ''))}<br/>"
            f"<b>Frecuencia:</b> {_escape(last.get('Frequency', ''))}<br/>"
            f"<b>Altura maxima:</b> {_escape(last.get('Max Drone Height (m)', ''))} m<br/>"
            f"<b>Coordenadas:</b> {_coord_text(last)}"
            ']]></description>'
        )
        lines.append(f'<styleUrl>#{style_id}</styleUrl>')
        lines.append(f'<Point><coordinates>{last["lon"]},{last["lat"]},0</coordinates></Point>')
        lines.append('</Placemark>')

    lines.extend(['</Document>', '</kml>'])
    Path(out_file).write_text('\n'.join(lines), encoding='utf-8')


def _write_last_seen_kml(df_points, out_file):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<kml xmlns="http://www.opengis.net/kml/2.2">', '<Document>', '<name>Ultima Posicion Drones</name>']

    by_drone = df_points.sort_values('Detect DT').groupby('Drone Key', dropna=False).tail(1)
    by_drone = by_drone.sort_values('Detect DT')

    for i, (_, row) in enumerate(by_drone.iterrows()):
        style_id = f'last_{i}'
        color = _kml_color(i)
        lines.append(f'<Style id="{style_id}"><IconStyle><color>{color}</color><scale>1.2</scale></IconStyle></Style>')
        desc = (
            '<![CDATA['
            f"<b>Drone Key:</b> {_escape(row['Drone Key'])}<br/>"
            f"<b>Modelo:</b> {_escape(row['Model'])}<br/>"
            f"<b>Device ID:</b> {_escape(row['Device ID'])}<br/>"
            f"<b>Source:</b> {_escape(row['Source'])}<br/>"
            f"<b>Ultima deteccion:</b> {_escape(row['Detect Time'])}<br/>"
            f"<b>Frecuencia:</b> {_escape(row.get('Frequency', ''))}<br/>"
            f"<b>Tag:</b> {_escape(row.get('tag', ''))}<br/>"
            f"<b>Altura maxima:</b> {_escape(row.get('Max Drone Height (m)', ''))} m<br/>"
            f"<b>Coordenadas:</b> {_coord_text(row)}"
            ']]>'
        )
        lines.append('<Placemark>')
        lines.append(f'<name>{_escape(row["Drone Key"])}</name>')
        lines.append(f'<styleUrl>#{style_id}</styleUrl>')
        lines.append(f'<description>{desc}</description>')
        lines.append(f'<Point><coordinates>{row["lon"]},{row["lat"]},0</coordinates></Point>')
        lines.append('</Placemark>')

    lines.extend(['</Document>', '</kml>'])
    Path(out_file).write_text('\n'.join(lines), encoding='utf-8')


def _write_txt_report(df_all, df_filtered, df_points, out_file, input_csv, filters):
    total = len(df_all)
    total_filtered = len(df_filtered)
    total_points = len(df_points)

    per_day = df_filtered.groupby('Fecha', dropna=True).size().sort_index()
    per_model = df_filtered.groupby('Model').size().sort_values(ascending=False)

    last_by_drone = df_points.sort_values('Detect DT').groupby('Drone Key', dropna=False).tail(1)
    last_by_drone = last_by_drone.sort_values('Detect DT', ascending=False)

    lines = []
    lines.append('REPORTE DE GEOREFERENCIACION - SKYEYE')
    lines.append('=' * 60)
    lines.append(f'Archivo fuente: {input_csv}')
    lines.append(f'Generado: {dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append('')
    lines.append('Filtros aplicados:')
    lines.append(f"- source: {filters.get('source') or 'todos'}")
    lines.append(f"- model: {filters.get('model') or 'todos'}")
    lines.append(f"- device: {filters.get('device') or 'todos'}")
    lines.append(f"- date: {filters.get('date') or 'todas'}")
    lines.append('')
    lines.append('Resumen general:')
    lines.append(f'- Registros totales en CSV: {total}')
    lines.append(f'- Registros tras filtros: {total_filtered}')
    lines.append(f'- Registros con coordenadas validas: {total_points}')
    lines.append(f'- Drones unicos con coordenadas: {df_points["Drone Key"].nunique()}')
    lines.append('')
    lines.append('Detecciones por dia:')
    if len(per_day) == 0:
        lines.append('- Sin datos para los filtros elegidos')
    else:
        for day, count in per_day.items():
            lines.append(f'- {day}: {count}')
    lines.append('')
    lines.append('Detecciones por dron/modelo:')
    if len(per_model) == 0:
        lines.append('- Sin datos para los filtros elegidos')
    else:
        for model, count in per_model.items():
            lines.append(f'- {model}: {count}')
    lines.append('')
    lines.append('Ultimo punto por dron (para busqueda):')
    if len(last_by_drone) == 0:
        lines.append('- Sin puntos georreferenciados')
    else:
        for _, row in last_by_drone.iterrows():
            lines.append(
                f"- Drone Key: {row['Drone Key']} | Modelo: {row['Model']} | Device ID: {row['Device ID']} | "
                f"Ultima deteccion: {row['Detect Time']} | Coordenadas: {row['lat']}, {row['lon']}"
            )

    Path(out_file).write_text('\n'.join(lines), encoding='utf-8')


def run_pipeline(input_csv, output_dir, source='drone', model_filter=None, device_filter=None, date_filter=None):
    df = _preprocess(input_csv)
    filtered = _apply_filters(df, source=source, model_filter=model_filter, device_filter=device_filter, date_filter=date_filter)

    points = filtered[filtered['has_coord']].copy()
    if points.empty:
        raise ValueError('No hay datos georreferenciados para esos filtros.')

    points['Drone Key'] = points.apply(_drone_key, axis=1)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    tracks_kml = out / 'trayectorias_drones.kml'
    last_kml = out / 'ultimas_posiciones_drones.kml'
    txt_report = out / 'reporte_georeferenciacion.txt'

    _write_tracks_kml(points, tracks_kml)
    _write_last_seen_kml(points, last_kml)
    _write_txt_report(
        df_all=df,
        df_filtered=filtered,
        df_points=points,
        out_file=txt_report,
        input_csv=input_csv,
        filters={
            'source': source,
            'model': model_filter,
            'device': device_filter,
            'date': date_filter,
        },
    )

    print('Pipeline completado')
    print(f'KML trayectorias: {tracks_kml}')
    print(f'KML ultimas posiciones: {last_kml}')
    print(f'Reporte TXT: {txt_report}')
    print(f'Drones exportados: {points["Drone Key"].nunique()}')
    print(f'Puntos georreferenciados: {len(points)}')


def main():
    parser = argparse.ArgumentParser(description='Pipeline SkyEye: georreferenciacion, trayectorias, ultimo punto y reporte TXT.')
    parser.add_argument('--input', default='Detection Report.csv', help='Ruta al CSV descargado de SkyEye')
    parser.add_argument('--outdir', default=None, help='Carpeta de salida. Si no se indica, se crea automaticamente')
    parser.add_argument('--source', default='drone', help='drone, rc o vacio para todos')
    parser.add_argument('--model', default=None, help='Filtro por texto de modelo')
    parser.add_argument('--device', default=None, help='Filtro exacto por Device ID')
    parser.add_argument('--date', default=None, help='Filtro fecha YYYY-MM-DD o YYYY.MM.DD')

    args = parser.parse_args()

    source = args.source.strip().lower()
    if source == '':
        source = None

    if args.outdir:
        outdir = args.outdir
    else:
        stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
        outdir = f'output_skyeye_{stamp}'

    run_pipeline(
        input_csv=args.input,
        output_dir=outdir,
        source=source,
        model_filter=args.model,
        device_filter=args.device,
        date_filter=args.date,
    )


if __name__ == '__main__':
    main()
