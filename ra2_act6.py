"""
Uso obligatorio de Desempaquetado (Unpacking): En la función
analizar_incidente, la extracción de campos debe realizarse obligatoriamente
asignando los 5 elementos de la tupla a 5 variables locales en una sola línea.

• Conversión segura para modificación: La función marcar_falso_positivo debe
convertir la tupla a lista con list(), realizar la edición, y re-convertirla a tupla con
tuple().
"""

# [FASE 1] Recolectando evidencia física inmutable...
PUERTOS_CRITICOS = (22, 80, 443, 3389)
trama_red = "2026-09-05 10:15:32_185.220.101.5_3389_a5c3e800fd2e411_ALTO".split("_")
evidencia_original = (
    trama_red[0],       # timestamp (str)
    trama_red[1],       # ip_origen (str)
    int(trama_red[2]),  # puerto_destino (int)
    trama_red[3],       # hash_malware (str)
    trama_red[4]        # severidad (str)
)


# [FASE 2] Iniciando análisis automatizado del incidente...
def analizar_incidente(evidencia: tuple) -> bool:
    """ ===== """
    fecha, ip, puerto, hash_evidencia, gravedad = evidencia

    print("------------------------------------------------------------------")
    print("🚨 ALERTA DE INCIDENTE DETECTADA")
    print("------------------------------------------------------------------")
    print(f"📅 Fecha y Hora: \t{fecha}")
    print(f"🌐 IP Origen: \t\t{ip}")

    if puerto in PUERTOS_CRITICOS:
        print(f"🎯 Puerto Destino: {puerto} [ALERTA: PUERTO CRÍTICO DETECTADO]")
    else:
        print(f"🎯 Puerto Destino: {puerto}")

    print(f"💾 Hash Evidencia: \t{hash_evidencia}")
    print(f"⚠️ Severidad: \t\t{gravedad}")



# PRUEBA GIT marica 2.0


def hola(mensaje):
    print(mensaje)




hola("print")



"""


Fecha y Hora: 2026-09-05 10:15:32
IP Origen: 185.220.101.5
Puerto Destino: 3389 [ALERTA: PUERTO CRÍTICO DETECTADO]
Hash Evidencia: a5c3e8...fd2e411
Severidad: ALTO
----------------------------------------------------------------------

"""


"""
• Lógica:
2. Evalúa si el puerto se encuentra en PUERTOS_CRITICOS utilizando el operador in.
3. Formatea la visualización del hash_evidencia para mostrar únicamente los primeros 6
caracteres y los últimos 7 caracteres unidos por puntos suspensivos (ejemplo:
a5c3e8...fd2e411).
4. Imprime en pantalla un panel detallado del incidente.
5. Retorna True si el puerto afectado es crítico; de lo contrario, retorna False.

"""








