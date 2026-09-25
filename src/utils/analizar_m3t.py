import re
from pathlib import Path
import pandas as pd
import sys
sys.path.insert(0, str(Path(__file__).parent / 'src' / 'utils'))
try:
    from src.utils.projections import ProjectionEngine
except ModuleNotFoundError:
    from projections import ProjectionEngine

# ── Leer Detection Report ──────────────────────────────────────────
dr = pd.read_csv('Detection Report.csv', sep=None, engine='python', encoding='latin-1')
dr.columns = [re.sub(r'^[\W_]+', '', c).strip() for c in dr.columns]
dr['Model_clean'] = dr['Model'].astype(str).str.replace(r'[^\x20-\x7E]+', '', regex=True).str.strip()

m3t_row = dr[dr['Model_clean'].str.upper().str.contains('M3T', na=False) &
             (dr['Source'].str.strip().str.lower() == 'drone')].iloc[0]

def parse_ll(val):
    nums = re.findall(r'[-+]?\d+\.\d+', str(val))
    if len(nums) >= 2:
        return float(nums[0]), float(nums[1])
    return None

last_det  = parse_ll(m3t_row['Last Detected Location (Lat Lng)'])
nearest   = parse_ll(m3t_row['Nearest Location [Lat Lng]'])
home_pt   = parse_ll(m3t_row['Home Location (Lat Lng)'])
rc_pt     = parse_ll(m3t_row['RC Location (Lat Lng)'])
height    = m3t_row.get('Max Drone Height (m)', '')
detect_t  = m3t_row['Detect Time']

# ── Leer PRUEBA1 (trayectoria del mismo Device ID) ──────────────────
p1 = pd.read_csv('PRUEBA1.csv', sep=None, engine='python', encoding='latin-1')
p1.columns = [re.sub(r'^[\W_]+', '', c).strip() for c in p1.columns]

proj = ProjectionEngine()

traj = []
for _, r in p1.iterrows():
    offset = float(str(r['Location']).strip())
    lat, lon = proj.calcular_coordenada_absoluta(offset)
    traj.append((lat, lon, str(r.get('Timestamp', '')).strip()))

inicio = traj[0]
fin    = traj[-1]

print('=== DJI M3T — BÚSQUEDA DE DRONE PERDIDO ===')
print(f'Device ID       : {m3t_row["Device ID"]}')
print(f'Ultima deteccion: {detect_t}')
print(f'Altura maxima   : {height} m')
print()
print(f'HOME (punto de despegue):')
if home_pt:
    print(f'  Lat: {home_pt[0]}  Lon: {home_pt[1]}')
    print(f'  → https://maps.google.com/?q={home_pt[0]},{home_pt[1]}')
print()
print(f'OPERADOR RC:')
if rc_pt:
    print(f'  Lat: {rc_pt[0]}  Lon: {rc_pt[1]}')
    print(f'  → https://maps.google.com/?q={rc_pt[0]},{rc_pt[1]}')
print()
print(f'INICIO trayectoria ({inicio[2]}):')
print(f'  Lat: {inicio[0]}  Lon: {inicio[1]}')
print(f'  → https://maps.google.com/?q={inicio[0]},{inicio[1]}')
print()
print(f'FIN trayectoria / ULTIMA POSICION ({fin[2]}):')
print(f'  Lat: {fin[0]}  Lon: {fin[1]}')
print(f'  → https://maps.google.com/?q={fin[0]},{fin[1]}')
print()
print(f'ULTIMA DETECCION SENSOR ({detect_t}):')
if last_det:
    print(f'  Lat: {last_det[0]}  Lon: {last_det[1]}')
    print(f'  → https://maps.google.com/?q={last_det[0]},{last_det[1]}')

# ── Generar KML enfocado en M3T ──────────────────────────────────────
def esc(v): return str(v).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<kml xmlns="http://www.opengis.net/kml/2.2">',
    '<Document><name>Busqueda DJI M3T Perdido</name>',
    # Estilos
    '<Style id="inicio"><IconStyle><color>ff00ff00</color><scale>1.4</scale></IconStyle></Style>',
    '<Style id="fin"><IconStyle><color>ff0000ff</color><scale>1.4</scale></IconStyle></Style>',
    '<Style id="home"><IconStyle><color>ff00ffff</color><scale>1.4</scale></IconStyle></Style>',
    '<Style id="rc"><IconStyle><color>ff00ff80</color><scale>1.2</scale></IconStyle></Style>',
    '<Style id="lastdet"><IconStyle><color>ff0080ff</color><scale>1.4</scale></IconStyle></Style>',
    '<Style id="tray"><LineStyle><color>ff1f77b4</color><width>3</width></LineStyle></Style>',
]

# HOME
if home_pt:
    lines += [
        '<Placemark><name>HOME (Despegue)</name><styleUrl>#home</styleUrl>',
        f'<description><![CDATA[Punto de despegue estimado<br/>Deteccion: {esc(detect_t)}]]></description>',
        f'<Point><coordinates>{home_pt[1]},{home_pt[0]},0</coordinates></Point></Placemark>',
    ]

# RC operador
if rc_pt:
    lines += [
        '<Placemark><name>OPERADOR RC</name><styleUrl>#rc</styleUrl>',
        f'<description><![CDATA[Posicion del operador con control remoto<br/>Deteccion: {esc(detect_t)}]]></description>',
        f'<Point><coordinates>{rc_pt[1]},{rc_pt[0]},0</coordinates></Point></Placemark>',
    ]

# INICIO trayectoria
lines += [
    '<Placemark><name>INICIO trayectoria</name><styleUrl>#inicio</styleUrl>',
    f'<description><![CDATA[Primera posicion registrada<br/>Hora: {esc(inicio[2])}]]></description>',
    f'<Point><coordinates>{inicio[1]},{inicio[0]},0</coordinates></Point></Placemark>',
]

# Trayectoria
lines.append('<Placemark><name>Recorrido M3T</name><styleUrl>#tray</styleUrl>')
lines.append('<LineString><tessellate>1</tessellate><coordinates>')
for lat, lon, _ in traj:
    lines.append(f'{lon},{lat},0')
lines.append('</coordinates></LineString></Placemark>')

# FIN trayectoria
lines += [
    '<Placemark><name>FIN trayectoria</name><styleUrl>#fin</styleUrl>',
    f'<description><![CDATA[Ultima posicion trayectoria<br/>Hora: {esc(fin[2])}<br/>Altura maxima: {esc(height)} m]]></description>',
    f'<Point><coordinates>{fin[1]},{fin[0]},0</coordinates></Point></Placemark>',
]

# Ultima deteccion sensor
if last_det:
    lines += [
        '<Placemark><name>ULTIMA DETECCION SENSOR</name><styleUrl>#lastdet</styleUrl>',
        f'<description><![CDATA[Ultimo punto registrado por sensor SkyEye<br/>Hora: {esc(detect_t)}<br/>Altura: {esc(height)} m]]></description>',
        f'<Point><coordinates>{last_det[1]},{last_det[0]},0</coordinates></Point></Placemark>',
    ]

lines += ['</Document></kml>']

out = Path('busqueda_M3T_perdido.kml')
out.write_text('\n'.join(lines), encoding='utf-8')
print()
print(f'KML generado: {out.resolve()}')
