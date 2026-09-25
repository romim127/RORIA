import pandas as pd
import re
import sys
from pathlib import Path


def _limpiar_columnas(df):
    df.columns = [re.sub(r'^[\W_]+', '', c).strip() for c in df.columns]
    return df


def _limpiar_modelo(valor):
    if pd.isna(valor):
        return 'Desconocido'
    return str(valor).replace('â', '—').replace('â\x80\x94', '—').strip()


def generar_reporte_html(input_file, output_file='reporte_detecciones.html'):
    df = pd.read_csv(input_file, sep=None, engine='python', encoding='latin-1')
    df = _limpiar_columnas(df)

    # Normalizar campos clave
    df['Model'] = df['Model'].apply(_limpiar_modelo)
    df['Source'] = df['Source'].fillna('Unknown').str.strip()
    df['Fecha'] = pd.to_datetime(
        df['Detect Time'].fillna(''), errors='coerce'
    ).dt.strftime('%Y-%m-%d')

    modelos = sorted(df['Model'].dropna().unique())
    fechas = sorted(df['Fecha'].dropna().unique())

    # Construir filas de la tabla
    filas_html = []
    for _, row in df.iterrows():
        source = str(row.get('Source', '')).strip().lower()
        badge_source = {
            'drone': '<span class="badge drone">DRONE</span>',
            'rc':    '<span class="badge rc">RC</span>',
        }.get(source, '<span class="badge unknown">?</span>')

        tag = str(row.get('tag', '')).strip()
        badge_tag = ''
        if tag == 'enemy':
            badge_tag = '<span class="badge enemy">ENEMIGO</span>'
        elif tag == 'suspicious':
            badge_tag = '<span class="badge suspicious">SOSPECHOSO</span>'

        lat_lon = str(row.get('Last Detected Location (Lat Lng)', '')).strip()
        maps_link = ''
        nums = re.findall(r'[-+]?\d+\.\d+', lat_lon)
        if len(nums) >= 2:
            maps_link = f'<a href="https://maps.google.com/?q={nums[0]},{nums[1]}" target="_blank">📍 Ver</a>'

        modelo = _limpiar_modelo(row.get('Model', ''))
        fecha = str(row.get('Fecha', ''))
        altura = str(row.get('Max Drone Height (m)', '')).strip()
        altura_txt = f'{altura} m' if altura and altura != 'nan' else '—'
        conteo = str(row.get('Detection Count', '')).strip()
        duracion = str(row.get('Stay Duration', '')).strip()
        frecuencia = str(row.get('Frequency', '')).strip()

        filas_html.append(
            f'<tr data-fecha="{fecha}" data-modelo="{modelo}" data-source="{source}">'
            f'<td>{fecha}</td>'
            f'<td>{modelo}</td>'
            f'<td>{badge_source}</td>'
            f'<td>{badge_tag}</td>'
            f'<td>{frecuencia}</td>'
            f'<td>{altura_txt}</td>'
            f'<td>{conteo}</td>'
            f'<td>{duracion}</td>'
            f'<td>{maps_link}</td>'
            f'</tr>'
        )

    opciones_fechas = '<option value="">Todos los días</option>' + ''.join(
        f'<option value="{f}">{f}</option>' for f in fechas
    )
    opciones_modelos = '<option value="">Todos los modelos</option>' + ''.join(
        f'<option value="{m}">{m}</option>' for m in modelos
    )

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte de Detecciones SkyEye</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  .filtros {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
  select, input {{ background: #161b22; color: #e6edf3; border: 1px solid #30363d;
                   padding: 8px 12px; border-radius: 6px; font-size: 14px; }}
  select:focus, input:focus {{ outline: none; border-color: #58a6ff; }}
  .resumen {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 14px 20px; min-width: 120px; text-align: center; }}
  .card .numero {{ font-size: 28px; font-weight: bold; color: #58a6ff; }}
  .card .label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #161b22; color: #8b949e; padding: 10px 12px; text-align: left;
        border-bottom: 2px solid #30363d; position: sticky; top: 0; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
  .badge.drone   {{ background: #1f4b8e; color: #79c0ff; }}
  .badge.rc      {{ background: #1a4731; color: #56d364; }}
  .badge.unknown {{ background: #3d2b00; color: #e3b341; }}
  .badge.enemy   {{ background: #6e1a1a; color: #ff7b72; }}
  .badge.suspicious {{ background: #3d2b00; color: #e3b341; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  #contador {{ color: #8b949e; font-size: 13px; margin-bottom: 10px; }}
  .oculto {{ display: none; }}
</style>
</head>
<body>
<h1>🛡️ Reporte de Detecciones SkyEye</h1>

<div class="resumen">
  <div class="card"><div class="numero" id="total-detecciones">{len(df)}</div><div class="label">Total detecciones</div></div>
  <div class="card"><div class="numero" id="total-drones">{df[df['Source'].str.lower()=='drone']['Model'].nunique()}</div><div class="label">Modelos únicos (drone)</div></div>
  <div class="card"><div class="numero" id="total-dias">{len(fechas)}</div><div class="label">Días con actividad</div></div>
  <div class="card"><div class="numero" id="total-enemy">{(df['tag']=='enemy').sum()}</div><div class="label">Marcados Enemigo</div></div>
</div>

<div class="filtros">
  <select id="filtro-fecha" onchange="filtrar()">
    {opciones_fechas}
  </select>
  <select id="filtro-modelo" onchange="filtrar()">
    {opciones_modelos}
  </select>
  <select id="filtro-source" onchange="filtrar()">
    <option value="">Drone y RC</option>
    <option value="drone">Solo DRONE</option>
    <option value="rc">Solo RC</option>
  </select>
  <input type="text" id="filtro-texto" placeholder="Buscar modelo..." oninput="filtrar()">
  <button onclick="resetFiltros()" style="background:#21262d;color:#e6edf3;border:1px solid #30363d;padding:8px 14px;border-radius:6px;cursor:pointer;">Limpiar filtros</button>
</div>

<div id="contador"></div>

<table id="tabla-detecciones">
  <thead>
    <tr>
      <th>Fecha</th>
      <th>Modelo</th>
      <th>Fuente</th>
      <th>Tag</th>
      <th>Frecuencia</th>
      <th>Altura</th>
      <th>Detecciones</th>
      <th>Duración</th>
      <th>Ubicación</th>
    </tr>
  </thead>
  <tbody>
    {''.join(filas_html)}
  </tbody>
</table>

<script>
function filtrar() {{
  const fecha   = document.getElementById('filtro-fecha').value;
  const modelo  = document.getElementById('filtro-modelo').value;
  const source  = document.getElementById('filtro-source').value;
  const texto   = document.getElementById('filtro-texto').value.toLowerCase();
  const filas   = document.querySelectorAll('#tabla-detecciones tbody tr');
  let visibles  = 0;
  filas.forEach(fila => {{
    const ok =
      (!fecha  || fila.dataset.fecha   === fecha)  &&
      (!modelo || fila.dataset.modelo  === modelo) &&
      (!source || fila.dataset.source  === source) &&
      (!texto  || fila.dataset.modelo.toLowerCase().includes(texto));
    fila.classList.toggle('oculto', !ok);
    if (ok) visibles++;
  }});
  document.getElementById('contador').textContent = `Mostrando ${{visibles}} de {len(df)} detecciones`;
}}

function resetFiltros() {{
  ['filtro-fecha','filtro-modelo','filtro-source'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('filtro-texto').value = '';
  filtrar();
}}

filtrar();
</script>
</body>
</html>"""

    Path(output_file).write_text(html, encoding='utf-8')
    print(f"REPORTE CREADO: {output_file}")
    print(f"   Total detecciones: {len(df)}")
    print(f"   Días con actividad: {', '.join(fechas)}")
    print(f"   Modelos detectados: {len(modelos)}")


if __name__ == '__main__':
    input_csv = sys.argv[1] if len(sys.argv) > 1 else 'Detection Report.csv'
    output_html = sys.argv[2] if len(sys.argv) > 2 else 'reporte_detecciones.html'
    generar_reporte_html(input_csv, output_html)
