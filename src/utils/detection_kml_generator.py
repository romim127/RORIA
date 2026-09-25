import argparse
import html
import re
from pathlib import Path

import pandas as pd


def _clean_columns(df):
    df.columns = [re.sub(r'^[\W_]+', '', str(c)).strip() for c in df.columns]
    return df


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


def _normalize_model(value):
    if pd.isna(value):
        return 'Unknown Model'
    text = str(value).strip()
    # Fix common mojibake from UTF-8 read as latin-1.
    try:
        text = text.encode('latin-1', errors='ignore').decode('utf-8', errors='ignore') or text
    except Exception:
        pass
    text = text.replace('DJI —', 'DJI -')
    text = text.replace('DJI â€”', 'DJI -')
    text = re.sub(r'[^\x20-\x7E]+', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip() or 'Unknown Model'


def _kml_color_for_index(index):
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
    return palette[index % len(palette)]


def _escape(value):
    return html.escape(str(value))


def _filter_by_date(df, date_value):
    if not date_value:
        return df

    # Accept either YYYY-MM-DD or YYYY.MM.DD
    normalized = date_value.replace('-', '.')
    detect_time = df['Detect Time'].fillna('').astype(str)
    return df[detect_time.str.startswith(normalized)]


def generate_detection_kml(
    input_csv,
    output_kml='detecciones_drone.kml',
    source='drone',
    model_filter=None,
    date_filter=None,
):
    df = pd.read_csv(input_csv, sep=None, engine='python', encoding='latin-1')
    df = _clean_columns(df)

    required = ['Source', 'Model', 'Detect Time', 'Last Detected Location (Lat Lng)']
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f'CSV invalido. Faltan columnas: {missing}')

    df['Source'] = df['Source'].fillna('').astype(str).str.strip().str.lower()
    df['Model'] = df['Model'].apply(_normalize_model)

    if source:
        df = df[df['Source'] == source.lower()]

    if model_filter:
        model_text = model_filter.lower().strip()
        df = df[df['Model'].str.lower().str.contains(model_text, na=False)]

    df = _filter_by_date(df, date_filter)

    points = []
    for _, row in df.iterrows():
        coords = _parse_latlon(row.get('Last Detected Location (Lat Lng)', ''))
        if coords is None:
            coords = _parse_latlon(row.get('Nearest Location [Lat Lng]', ''))
        if coords is None:
            continue

        points.append(
            {
                'lat': coords[0],
                'lon': coords[1],
                'model': row.get('Model', 'Unknown Model'),
                'source': row.get('Source', ''),
                'detect_time': row.get('Detect Time', ''),
                'record_id': row.get('Record ID', ''),
                'height': row.get('Max Drone Height (m)', ''),
                'count': row.get('Detection Count', ''),
                'tag': row.get('tag', ''),
                'frequency': row.get('Frequency', ''),
                'sensor': row.get('Sensor', ''),
            }
        )

    if not points:
        raise ValueError('No hay puntos geograficos para exportar con esos filtros.')

    models = sorted({p['model'] for p in points})
    model_style = {m: f'style_{i}' for i, m in enumerate(models)}

    lines = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append('<kml xmlns="http://www.opengis.net/kml/2.2">')
    lines.append('<Document>')
    lines.append('<name>Detecciones SkyEye</name>')

    for i, model in enumerate(models):
        style_id = model_style[model]
        color = _kml_color_for_index(i)
        lines.append(f'<Style id="{style_id}">')
        lines.append('<IconStyle>')
        lines.append(f'<color>{color}</color>')
        lines.append('<scale>1.1</scale>')
        lines.append('<Icon><href>http://maps.google.com/mapfiles/kml/pushpin/ylw-pushpin.png</href></Icon>')
        lines.append('</IconStyle>')
        lines.append('</Style>')

    for p in points:
        style_id = model_style[p['model']]
        description = (
            '<![CDATA['
            f"<b>Modelo:</b> {_escape(p['model'])}<br/>"
            f"<b>Fuente:</b> {_escape(p['source'])}<br/>"
            f"<b>Hora deteccion:</b> {_escape(p['detect_time'])}<br/>"
            f"<b>Record ID:</b> {_escape(p['record_id'])}<br/>"
            f"<b>Altura maxima:</b> {_escape(p['height'])} m<br/>"
            f"<b>Cantidad detecciones:</b> {_escape(p['count'])}<br/>"
            f"<b>Tag:</b> {_escape(p['tag'])}<br/>"
            f"<b>Frecuencia:</b> {_escape(p['frequency'])}<br/>"
            f"<b>Sensor:</b> {_escape(p['sensor'])}"
            ']]>'
        )
        lines.append('<Placemark>')
        lines.append(f'<name>{_escape(p["model"])}</name>')
        lines.append(f'<styleUrl>#{style_id}</styleUrl>')
        lines.append(f'<description>{description}</description>')
        lines.append('<Point>')
        lines.append(f'<coordinates>{p["lon"]},{p["lat"]},0</coordinates>')
        lines.append('</Point>')
        lines.append('</Placemark>')

    lines.append('</Document>')
    lines.append('</kml>')

    Path(output_kml).write_text('\n'.join(lines), encoding='utf-8')

    print(f'KML creado: {output_kml}')
    print(f'Puntos exportados: {len(points)}')
    print(f'Modelos incluidos: {len(models)}')


def main():
    parser = argparse.ArgumentParser(description='Genera un KML de detecciones para Google Earth.')
    parser.add_argument('--input', default='Detection Report.csv', help='CSV de entrada')
    parser.add_argument('--output', default='detecciones_drone.kml', help='KML de salida')
    parser.add_argument('--source', default='drone', help='drone, rc o vacío para todos')
    parser.add_argument('--model', default=None, help='Filtro de modelo (contiene texto)')
    parser.add_argument('--date', default=None, help='Filtro fecha YYYY-MM-DD o YYYY.MM.DD')

    args = parser.parse_args()
    source = args.source.strip().lower()
    if source == '':
        source = None

    generate_detection_kml(
        input_csv=args.input,
        output_kml=args.output,
        source=source,
        model_filter=args.model,
        date_filter=args.date,
    )


if __name__ == '__main__':
    main()
