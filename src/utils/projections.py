class ProjectionEngine:
	def calcular_coordenada_absoluta(self, offset_x):
		# Apply the correction constant from reverse engineering to normalize SkyEye to GPS.
		lon_real = offset_x + 33.099548
		# Keep a fixed latitude reference for Lujan.
		lat_real = -33.096346

		return round(lat_real, 6), round(lon_real, 6)

