"""
Procesa tramas de red como evidencias inmutables (tuplas), analiza puertos
críticos y permite el saneamiento seguro mediante conversión temporal a lista
"""

PUERTOS_CRITICOS = (22, 80, 443, 3389)


def analizar_incidente(evidencia: tuple) -> bool:
    """
    Analiza una evidencia forense inmutable y evalúa si el puerto es crítico

    :param evidencia: Tupla con la estructura
        (timestamp, ip_origen, puerto_destino, hash_malware, severidad)
    :return:    True si el puerto destino está en PUERTOS_CRITICOS,
                False en caso contrario
    """

    # Desempaquetado obligatorio en una sola línea
    fecha, ip, puerto, hash_evidencia, gravedad = evidencia
    
    es_critico = puerto in PUERTOS_CRITICOS

    # Formateo del hash: primeros 6 + "..." + últimos 7 caracteres
    hash_formateado = hash_evidencia[:6] + "..." + hash_evidencia[-7:]

    print("------------------------------------------------------------------")
    print("🚨 ALERTA DE INCIDENTE DETECTADA")
    print("------------------------------------------------------------------")
    print(f"📅 Fecha y Hora: \t{fecha}")
    print(f"🌐 IP Origen: \t\t{ip}")

    if es_critico:
        print(f"🎯 Puerto Destino: {puerto} [ALERTA: PUERTO CRÍTICO DETECTADO]")
    else:
        print(f"🎯 Puerto Destino: {puerto}")

    print(f"💾 Hash Evidencia: \t{hash_formateado}")
    print(f"⚠️ Severidad: \t\t{gravedad}")


def marcar_falso_positivo(evidencia: tuple) -> tuple:
    """
    Convierte la tupla a lista, modifica la severidad (último elemento)
    y re-convierte a tupla inmutable

    :param evidencia: Tupla original con los 5 campos del incidente
    :return: Nueva tupla inmutable con la severidad actualizada
    """

    lista_temporal = list(evidencia)
    lista_temporal[-1] = "FALSO_POSITIVO"
    return tuple(lista_temporal)


# Flujo principal
print("🕵️ SOC INCIDENT RESPONSE & FORENSICS TOOL - UNIT 2.6")
print("Cargando bases de datos de puertos críticos... OK")


print("[FASE 1] Recolectando evidencia física inmutable...")

trama_red = "2026-09-05 10:15:32_185.220.101.5_3389_a5c3e800fd2e411_ALTO"
campos = trama_red.split("_")

timestamp = campos[0]
ip_origen = campos[1]
puerto_destino = int(campos[2])
hash_malware = campos[3]
severidad = campos[4]

evidencia_original = (
    timestamp, ip_origen, puerto_destino, hash_malware, severidad)

print("Evidencia bloqueada en memoria con éxito. "
      f"Tipo: {type(evidencia_original)}")


print("[FASE 2] Iniciando análisis automatizado del incidente...")
analizar_incidente(evidencia_original)

respuesta = input("¿Deseas mitigar este incidente como Falso Positivo? (s/n): ")
respuesta = respuesta.strip().lower()


if respuesta == "s":
    print("[FASE 3] Saneando base de datos forense...")
    print("Convirtiendo datos temporales para su edición... OK")
    
    evidencia_final = marcar_falso_positivo(evidencia_original)
    
    print("Re-bloqueando evidencia final del incidente... OK")
    print("[REPORTE DE AUDITORÍA FINAL]")
    print(f"Contenido final seguro: {evidencia_final}")
else:
    evidencia_final = evidencia_original
    print("[FASE 3] Mitigación cancelada. Se conserva la evidencia original.")
    print(f"Contenido final: {evidencia_final}")

# Verificación de integridad física: intento de mutación bloqueado
try:
    evidencia_final[2] = 9999
    print("ERROR: La tupla ha sido alterada (esto no debería ocurrir).")
except TypeError:
    print("Verificación de integridad física: Intento de alteración de tupla "
          "final -> Bloqueado por el intérprete de Python (TypeError).")