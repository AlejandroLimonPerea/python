"""
Procesa tramas de red como evidencias inmutables (tuplas), analiza puertos
críticos y permite el saneamiento seguro mediante conversión temporal a lista
"""

PUERTOS_CRITICOS = (22, 80, 443, 3389)


# [FASE 2] Iniciando análisis automatizado del incidente...
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

    # Formateo del hash: primeros 6 + "..." + últimos 7 caracteres
    hash_formateado = hash_evidencia[:6] + "..." + hash_evidencia[-7:]

    print("------------------------------------------------------------------")
    print("🚨 ALERTA DE INCIDENTE DETECTADA")
    print("------------------------------------------------------------------")
    print(f"📅 Fecha y Hora: \t{fecha}")
    print(f"🌐 IP Origen: \t\t{ip}")

    if puerto in PUERTOS_CRITICOS:
        print(f"🎯 Puerto Destino: {puerto} [ALERTA: PUERTO CRÍTICO DETECTADO]")
    else:
        print(f"🎯 Puerto Destino: {puerto}")

    print(f"💾 Hash Evidencia: \t{hash_formateado}")
    print(f"⚠️ Severidad: \t\t{gravedad}")


def marcar_falso_positivo(evidencia: tuple) -> tuple:
    """
    Escanea una evidencia forense marcándola como FALSO_POSITIVO.

    Convierte la tupla a lista, modifica la severidad (último elemento)
    y re-convierte a tupla inmutable

    :param evidencia: Tupla original con los 5 campos del incidente
    :return: Nueva tupla inmutable con la severidad actualizada
    """


"""
3. Fase 3: Mitigación y Re-bloqueo (marcar_falso_positivo)
• Firma: marcar_falso_positivo(evidencia: tuple) -> tuple
• Docstring: Explicación formal de la función.
• Lógica:
1. Recibe la tupla inmutable evidencia.
2. Convierte la tupla a lista usando list().
3. Modifica la posición correspondiente a la severidad (último elemento) asignándole el
valor "FALSO_POSITIVO".
4. Convierte de nuevo la lista a tupla inmutable mediante tuple().
5. Retorna la nueva tupla saneada.
"""





# [FASE 1] Recolectando evidencia física inmutable...
trama_red = "2026-09-05 10:15:32_185.220.101.5_3389_a5c3e800fd2e411_ALTO".split("_")
evidencia_original = (
    trama_red[0],       # timestamp (str)
    trama_red[1],       # ip_origen (str)
    int(trama_red[2]),  # puerto_destino (int)
    trama_red[3],       # hash_malware (str)
    trama_red[4]        # severidad (str)
)


"""
• Conversión segura para modificación: La función marcar_falso_positivo debe
convertir la tupla a lista con list(), realizar la edición, y re-convertirla a tupla con
tuple().
"""


















