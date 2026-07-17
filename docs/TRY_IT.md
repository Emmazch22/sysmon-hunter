# Cómo probar Sysmon Hunter

Guía para instalar el proyecto en tu laptop y darle una vuelta completa: qué instalar,
cómo levantarlo, qué datos cargar, y qué mirar en la interfaz para hacerte una idea
real de qué hace.

Sysmon Hunter es un motor de detección: recibe eventos de Sysmon (Windows), los
compara contra ~50 reglas tipo Sigma, correlaciona lo que está relacionado en un
mismo incidente, y te lo muestra en una consola web con árbol de procesos, línea de
tiempo, y contexto de MITRE ATT&CK. No necesitas Windows ni Sysmon real para
probarlo — todo se simula con datos de ejemplo o con archivos `.evtx` reales.

Tiempo estimado: 10-15 min con Docker, 15-20 min sin Docker.

---

## Opción A — Docker (la más rápida)

Requiere [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado
y corriendo.

```bash
git clone <url-del-repo>
cd sysmon-hunter
docker compose up --build
```

Espera a que el log diga que Uvicorn está escuchando, y abre
<http://localhost:8000>. Listo, salta directo a la sección **"Cargar datos de
ejemplo"** más abajo (los comandos son los mismos, solo corren en tu máquina local
apuntando al contenedor, no dentro de él).

Para parar todo: `Ctrl+C` y luego `docker compose down` (usa `docker compose down -v`
si además quieres borrar la base de datos).

---

## Opción B — Python local

### Requisitos

- Python 3.11 o superior (`python3 --version` para chequear)
- Git

### Pasos

```bash
git clone <url-del-repo>
cd sysmon-hunter

python -m venv .venv
source .venv/bin/activate          # Windows (PowerShell): .venv\Scripts\Activate.ps1

pip install -r requirements.txt

python -m alembic upgrade head     # crea la base de datos (data/hunter.db)
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Deja esa terminal corriendo (es el servidor) y abre:

- Consola: <http://localhost:8000>
- Documentación de la API: <http://localhost:8000/api/docs>

Al principio va a estar vacío — eso es normal, todavía no hay eventos.

---

## Cargar datos de ejemplo

Con el servidor corriendo, en **otra terminal** (con el mismo entorno virtual
activado si usaste la Opción B):

```bash
python scripts/seed_apt.py             # una intrusión completa, un solo incidente
python scripts/seed_demo.py            # variedad: varios incidentes chicos y medianos
python scripts/seed_rw.py              # cadena de ransomware completa, un incidente
python scripts/seed_full_coverage.py   # dispara las ~50 reglas del motor de una vez
```

Puedes correr uno, varios, o todos — cada uno agrega datos nuevos, no borra lo que ya
había. Si quieres arrancar de cero entre pruebas, hay un botón de reset en el panel de
la consola (ícono de engranaje), o puedes borrar `data/hunter.db` y volver a correr
`alembic upgrade head`.

Recomendación de orden para una primera vuelta: `seed_apt.py` primero (da el incidente
más narrativo, con árbol profundo y buena historia), luego `seed_demo.py` para ver
variedad.

---

## Analizar una muestra real (.evtx)

Si tu amigo quiere ver algo más "real" que datos sintéticos, puede tomar cualquier
`.evtx` de Sysmon — de una VM propia, o del repositorio público
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (cada
archivo ahí representa una técnica de ATT&CK distinta):

```bash
python scripts/replay_evtx.py --file ruta/al/archivo.evtx
```

Esto reproduce los eventos del archivo contra el servidor que ya tienes corriendo,
como si fueran telemetría en vivo. Vale la pena probar más de un archivo del corpus:
algunos disparan varias reglas, otros — como pasó en esta misma sesión de desarrollo
con una muestra de Emotet — solo una, lo cual es interesante en sí mismo (te obliga a
mirar por qué el resto del comportamiento no calzó con ninguna regla).

---

## Qué mirar en la interfaz (tour de funcionalidades)

Con datos cargados, esto es lo que vale la pena que tu amigo explore:

**Dashboard principal** — tarjetas de incidentes ordenadas por severidad/score. Cada
una resume host, cantidad de detecciones, técnicas ATT&CK involucradas, y hace cuánto
ocurrió.

**Expandir un incidente** — perfil de comportamiento en lenguaje llano (qué pasó, fase
por fase, cada línea respaldada por técnicas ATT&CK) seguido del árbol de procesos
completo. Nodos con detección salen coloreados por severidad; procesos de contexto sin
detección salen huecos.

**Botón "Explore"** — abre el incidente en una pestaña nueva, a pantalla completa, con
tres vistas alternables: árbol de procesos, línea de tiempo, y un listado plano de
logs. El árbol y la línea de tiempo se pueden arrastrar (pan) y hacer zoom con la
rueda del mouse — pensado para incidentes con árboles muy anchos o profundos que no
caben en la columna del dashboard.

**Buscador** — barra de búsqueda con sintaxis de filtros: prueba texto libre
(`mimikatz`), o filtros de campo como `host:`, `severity:`, `rule:`, `technique:`,
`user:`, `command_line:`, `actionable:true`, y combinaciones (`host:WKSTN-04
severity:high`). El botón "?" al lado de la barra muestra la sintaxis completa.

**Triage** — cada incidente tiene un menú "Set verdict" (falso positivo, benigno,
malicioso, etc.) y un botón para cerrarlo. Hay un filtro de pestaña "Closed" para ver
los ya resueltos.

**Modo oscuro/claro** — ícono de engranaje o toggle en el header.

**Técnicas MITRE ATT&CK** — los badges de técnica (`T1003`, etc.) son clickeables y
abren un modal con contexto de la matriz ATT&CK.

**Reporte / notas del analista** — la vista de incidente completo (página dedicada,
no el popup) tiene espacio para notas y, si está disponible, exportar un reporte.

---

## Opcional: enriquecimiento de IOCs

Sin configurar nada, el motor funciona igual — los proveedores de reputación
simplemente reportan "no disponible". Si tu amigo quiere ver enriquecimiento real de
IPs (AbuseIPDB, VirusTotal), puede crear un archivo `.env` en la raíz del proyecto:

```
HUNTER_ABUSEIPDB_API_KEY=...    # gratis en https://www.abuseipdb.com/register
HUNTER_VIRUSTOTAL_API_KEY=...   # gratis en https://www.virustotal.com/gui/join-us
```

Y reiniciar el servidor.

---

## Correr los tests (opcional, para quien quiera meterse al código)

```bash
pip install pytest pytest-asyncio
python -m pytest        # ~280 tests
```

Cada regla de detección tiene un caso que la dispara y otro que confirma que no da
falso positivo — es una buena forma de entender qué evalúa cada regla sin leer el YAML.

---

## Problemas comunes

**"Address already in use" al levantar el servidor** — algo más está usando el puerto
8000. Cambia el puerto: `--port 8001` (y ajusta la URL de la consola y de
`replay_evtx.py --url` si lo usas).

**`ModuleNotFoundError` al correr scripts** — el entorno virtual no está activado en
esa terminal. Repite el `source .venv/bin/activate` (o `.venv\Scripts\Activate.ps1`
en Windows) en cada terminal nueva que abras.

**La consola carga pero no aparece nada nuevo tras correr un seed script** — revisa
que el seed script esté apuntando al mismo puerto que el servidor (por defecto ambos
usan `:8000`), y que no haya un error impreso en la terminal del seed script.

**Error de base de datos corrupta / "database disk image is malformed"** — pasa si el
servidor se mató de forma abrupta a mitad de una escritura. Solución: para el
servidor, borra `data/hunter.db`, y vuelve a correr `python -m alembic upgrade head`.
Se pierde lo que había cargado, pero es rápido volver a sembrar con los scripts de
arriba.

**En Windows, `pip install` falla en algún paquete con extensión C** — instala
["Microsoft C++ Build Tools"](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
o, más simple, usa la Opción A (Docker) en su lugar.

**Cambios en la interfaz no se ven** (si tu amigo edita algo y prueba) — fuerza un
refresh sin caché en el navegador (`Ctrl+Shift+R` / `Cmd+Shift+R`).

---

## Escenarios que vale la pena probar específicamente

Si tu amigo tiene tiempo y quiere darte feedback más allá de "funciona o no":

- Estado vacío (recién clonado, sin sembrar nada) — ¿la consola comunica bien que no
  hay datos, o se ve como un error?
- Un incidente único y profundo (`seed_apt.py`) vs. muchos incidentes chicos
  (`seed_demo.py`) — ¿el dashboard escala bien con volumen?
- Un árbol de procesos ancho/profundo en la vista "Explore" — ¿el pan y zoom se
  sienten naturales?
- Cerrar un incidente, ponerle un verdict, y volver a abrirlo — ¿el estado persiste
  bien?
- Búsquedas combinando varios filtros a la vez.
- Reproducir dos o tres `.evtx` distintos del corpus EVTX-ATTACK-SAMPLES — ¿cuáles
  disparan varias reglas y cuáles solo una o ninguna? Eso último es útil como reporte
  de gaps de detección.
- Modo oscuro vs. claro en distintos tamaños de ventana (achicar el navegador para
  simular una laptop chica).
- Con y sin llaves de enriquecimiento de IOC configuradas.

---

## Dónde reportar lo que encuentre

Cualquier bug, confusión de UI, o regla que debería haber disparado y no lo hizo —
mejor si viene con: qué script/archivo usó para sembrar datos, qué esperaba ver, y
qué vio en su lugar (una captura ayuda mucho).
