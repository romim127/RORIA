import pandas as pd
import re

try:
    from src.utils.projections import ProjectionEngine
except ModuleNotFoundError:
    from projections import ProjectionEngine


def _extraer_latlon(value):
    """Extrae (lat, lon) de un string como '-33.096346 -69.034453'."""
    texto = str(value).strip()
    numeros = [float(x) for x in re.findall(r'[-+]?\d+\.\d+', texto)]
    if len(numeros) >= 2:
        return round(numeros[0], 6), round(numeros[1], 6)
    return None


def _es_formato_skyeye_nuevo(df):
    """Detecta si el CSV es el formato nuevo de SkyEye (tiene columna Source y Last Detected Direction)."""
    return 'Source' in df.columns and 'Last Detected Location (Lat Lng)' in df.columns


def generar_kml_preciso(input_file, output_file):
    df = pd.read_csv(input_file, sep=None, engine='python', encoding='latin-1')

    if _es_formato_skyeye_nuevo(df):
        # --- Formato SkyEye nuevo: filtrar solo filas de drone, usar lat/lon reales ---
        print("📡 Formato SkyEye detectado: usando coordenadas GPS reales del drone")
        df_drone = df[df['Source'].str.strip().str.lower() == 'drone'].copy()
        if df_drone.empty:
            raise ValueError("No se encontraron filas con Source='drone' en el archivo.")

        coordenadas = []
        for val in df_drone['Last Detected Location (Lat Lng)']:
            coords = _extraer_latlon(val)
            if coords:
                coordenadas.append(coords)

        if not coordenadas:
            raise ValueError("No se pudieron extraer coordenadas de 'Last Detected Location (Lat Lng)'.")

        # Home: primera coordenada del drone
        home_lat, home_lon = coordenadas[0]

        # Si hay RC, usamos su posición como referencia de operador (marcador extra)
        df_rc = df[df['Source'].str.strip().str.lower() == 'rc']
        rc_coords = None
        if not df_rc.empty:
            rc_coords = _extraer_latlon(df_rc['Last Detected Location (Lat Lng)'].iloc[0])

    else:
        # --- Formato viejo: proyección desde offset ---
        print("📡 Formato clásico detectado: usando proyección desde offset")
        proyector = ProjectionEngine()

        def _parsear_offset(value):
            texto = str(value).strip()
            numeros = [float(x) for x in re.findall(r'[-+]?\d+(?:\.\d+)?', texto)]
            if len(numeros) >= 2 and -90 <= numeros[0] <= 90:
                return round(numeros[0], 6), round(numeros[1], 6)
            if len(numeros) >= 1:
                return proyector.calcular_coordenada_absoluta(numeros[0])
            raise ValueError(f"Location invalida: {value}")

        coordenadas = [_parsear_offset(loc) for loc in df['Location']]
        home_lat, home_lon = coordenadas[0]
        if 'Home Location (Lat Lng)' in df.columns:
            home_val = str(df['Home Location (Lat Lng)'].iloc[0]).strip()
            if home_val and home_val.lower() != 'nan':
                parsed = _parsear_offset(home_val)
                if parsed:
                    home_lat, home_lon = parsed
        rc_coords = None

    # --- Escritura del KML ---
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>')
        f.write('<kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>Trayectoria_Completa</name>')
        f.write('<Style id="pathStyle"><LineStyle><color>ff0000ff</color><width>3</width></LineStyle></Style>')
        f.write('<Style id="rcStyle"><IconStyle><color>ff00ff00</color><scale>1.2</scale></IconStyle></Style>')

        # Marcador INICIO (primera posición del drone)
        f.write(f'<Placemark><name>INICIO</name><Point><coordinates>{home_lon},{home_lat},0</coordinates></Point></Placemark>')

        # Marcador OPERADOR RC (si existe)
        if rc_coords:
            f.write(f'<Placemark><name>OPERADOR (RC)</name><styleUrl>#rcStyle</styleUrl><Point><coordinates>{rc_coords[1]},{rc_coords[0]},0</coordinates></Point></Placemark>')

        # Trayectoria
        f.write('<Placemark><name>Recorrido Drone</name><styleUrl>#pathStyle</styleUrl><LineString><coordinates>')
        for lat, lon in coordenadas:
            f.write(f'{lon},{lat},0 ')
        f.write('</coordinates></LineString></Placemark>')

        # Marcador FIN
        fin_lat, fin_lon = coordenadas[-1]
        f.write(f'<Placemark><name>FIN</name><Point><coordinates>{fin_lon},{fin_lat},0</coordinates></Point></Placemark>')

        f.write('</Document></kml>')

    print(f"✅ ARCHIVO CREADO: {output_file}")
    print(f"   Puntos en trayectoria: {len(coordenadas)}")
    if rc_coords:
        print(f"   Posición operador RC: {rc_coords[0]}, {rc_coords[1]}")

if __name__ == "__main__":
    generar_kml_preciso('PRUEBA1.csv', 'trayectoria_completa.kml')