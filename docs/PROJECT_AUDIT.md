# Análisis del proyecto — julio 2026

Revisión completa del código (no solo lectura del README): backend (~4.650 líneas
Python en `backend/`), frontend (~6.100 líneas en `frontend/`), 49 reglas YAML,
3.160 líneas de tests, y 3.200 líneas de scripts. Esto es lo que encontré, con
archivo y línea concretos donde aplica, y qué haría con cada cosa.

---

## En qué está bien parado el proyecto

Vale la pena decirlo antes de la lista de problemas, porque cambia qué tan urgente
es cada uno:

- **Cobertura de tests real, no de fachada.** Las 49 reglas tienen, cada una, un
  caso que la dispara y uno que confirma que no da falso positivo (verificado
  contra `tests/test_rules.py`, 1:1 sin excepciones). Eso es raro incluso en
  proyectos comerciales de detección.
- **Separación de capas limpia.** `normalize → ProcessTree.observe → matcher →
  correlator → persist → broadcast` está bien aislado; cada pieza es testeable
  sin HTTP. `ingest.py` en particular es deliberadamente delgado (43 líneas) para
  no dejar que la lógica de detección se filtre al handler.
- **Documentación de decisiones dentro del código.** Los docstrings explican el
  *por qué*, no solo el qué (`config.py`, `beacon.py`, `main.py`). Esto es raro y
  vale más que un wiki externo que se desactualiza.
- **Degradación explícita, no silenciosa.** El enriquecimiento de IOCs sin API
  keys, o una regla que falla al cargar, se reportan en `/health` en vez de fallar
  en silencio.

---

## Qué falta

### 1. Autenticación — cero, en ningún endpoint

`backend/main.py` no registra ningún middleware de auth, y ningún router usa
`Depends()` para validar nada. Eso incluye:

- `DELETE /admin/database` (`backend/api/admin.py`) — borra toda la base de datos,
  sin confirmación ni credencial.
- `POST /ingest` — acepta cualquier payload de cualquier origen.
- El WebSocket `/ws` — cualquiera en la red puede conectarse y ver detecciones en
  vivo.

Y el servidor está pensado para bindear a `0.0.0.0` por defecto (`config.py:26`,
y el comentario en `docker-compose.yml` lo confirma explícitamente: "bound to all
interfaces on purpose"). Es decir, el diseño asume que un agente Winlogbeat en otra
máquina de la red debe poder llegar a `/ingest` — lo cual es razonable para un lab,
pero significa que cualquier otra máquina en esa misma red también puede llegar a
`/admin/database`.

**Cómo lo mejoraría:** una API key simple por header (`X-Hunter-Key`), verificada
en un `Depends()` compartido, aplicada al menos a `/admin/*` y opcionalmente a
`/ingest`. No hace falta OAuth ni sesiones — es un lab tool, pero uno que borra
datos con un DELETE sin fricción no debería quedar así por defecto. Alternativa más
barata: documentar en el README, en rojo, que esto no debe exponerse fuera de
`127.0.0.1` sin ponerle algo delante (nginx + basic auth, un túnel, etc.), y que
Docker Compose no debería bindear `0.0.0.0` salvo que el usuario lo pida
explícitamente.

### 2. SQLite sin WAL — la causa raíz de la corrupción que ya viste esta sesión

`backend/models/db.py` no configura `PRAGMA journal_mode=WAL` en ningún lado. Con
el modo por defecto (`journal`), un proceso de Uvicorn matado a mitad de una
escritura (`kill`, `Ctrl+C` duro, crash) puede dejar la base de datos en un estado
corrupto — que es exactamente lo que pasó dos veces en esta misma sesión de
desarrollo con `data/hunter.db`. WAL no lo hace imposible, pero lo hace mucho más
difícil, porque separa el archivo de datos del log de escritura.

**Cómo lo mejoraría:** una línea en el `init_db()` de `db.py`:
`PRAGMA journal_mode=WAL;` al abrir la conexión. Es prácticamente gratis y elimina
la clase de bug que más tiempo te hizo perder en esta sesión.

### 3. Sin CI

No hay `.github/workflows/`, ni pre-commit, ni ningún gate automático. Ahora mismo
la única red de seguridad es correr `pytest` a mano antes de cada commit — lo cual
has hecho consistentemente, pero es un hábito, no una garantía.

**Cómo lo mejoraría:** un workflow de GitHub Actions mínimo — `pip install -r
requirements.txt && pytest` en cada push/PR. 15 minutos de trabajo, y evita que un
commit rompa `main` sin que nadie se entere hasta la próxima sesión.

### 4. Sin linting/type-checking automatizado

No hay `ruff`, `black`, ni `mypy` en `requirements.txt` ni configurados en ningún
archivo. El código que vi está bien escrito a mano, pero eso no escala si el
proyecto crece o alguien más contribuye.

**Cómo lo mejoraría:** `ruff` cubre lint + formato en una sola herramienta y es
rápido. Un `ruff.toml` de 5 líneas y agregarlo al CI del punto anterior.

### 5. Sin `LICENSE`

El repo no tiene archivo de licencia. Si en algún momento quieres que alguien más
lo use, lo mire, o lo referencie (por ejemplo, para que tu amigo lo pruebe con
confianza de qué puede y no puede hacer con el código), esto importa.

**Cómo lo mejoraría:** elegir una (MIT es la default razonable para un proyecto de
portfolio/investigación) y agregar `LICENSE` a la raíz.

### 6. Sin `.env.example`

`config.py` documenta bien las variables `HUNTER_*` en comentarios, y el README
menciona las dos de enriquecimiento, pero no hay un archivo `.env.example` que
alguien pueda copiar a `.env` y completar. Cualquiera que clone el repo tiene que
leer `config.py` línea por línea para saber qué puede configurar.

**Cómo lo mejoraría:** un `.env.example` con las ~10 variables de `Settings` y un
comentario de una línea cada una — se genera casi copiando `config.py`.

### 7. Frontend sin ningún test

`backend/` tiene 3.160 líneas de tests. `frontend/` (6.100 líneas de HTML/JS/CSS)
tiene cero. Toda la lógica de renderizado del árbol de procesos, la línea de
tiempo, el parseo de búsqueda en el cliente, etc., depende de pruebas manuales.
Dado que ya tuviste bugs de renderizado dos veces esta sesión (el popup cortado),
esto no es un problema teórico.

**Cómo lo mejoraría:** no hace falta un framework pesado. Aunque sea un puñado de
tests con `vitest` o incluso `node --test` sobre las funciones puras que ya
identifiqué duplicadas (ver más abajo) — `humanGap`, `clockTime`, `baseName`,
el parser de búsqueda del lado del cliente si existe — daría cobertura donde más
se repiten bugs.

---

## Qué sobra

### 1. `backend/queue/` — módulo muerto

`backend/queue/__init__.py` y `backend/queue/stream.py` están completamente
vacíos (0 líneas) y nada en el proyecto los importa. Es probablemente el
esqueleto de una idea (una cola de eventos real, tal vez para desacoplar
`/ingest` del procesamiento síncrono) que nunca se implementó.

**Qué hacer:** bórralo, o si la idea sigue viva, deja un comentario en el README
bajo "Notes" explicando la intención en una línea. Un directorio vacío en el
árbol del proyecto no comunica nada por sí solo.

### 2. Cuatro archivos `.jsonl` sueltos en la raíz del repo

`appcmd.jsonl`, `keylogger.jsonl`, `openurl.jsonl`, `ostap.jsonl` (174 KB en
total) están trackeados en git, en la raíz del proyecto, y no los referencia
ningún script, test, ni documento. Por el contenido (eventos Sysmon crudos de
`EVTX-ATTACK-SAMPLES`) son casi con certeza sobras de la sesión donde
descargaste y analizaste 166 EVTX reales contra el motor de reglas.

**Qué hacer:** si sirven como fixtures de prueba, muévelos a `tests/fixtures/` o
`samples/` con un comentario de qué son y por qué se guardan. Si no, `git rm`
y listo — no deberían vivir sueltos en la raíz confundiéndose con configuración
del proyecto.

### 3. `scripts/atomic_runbook.md` y `tests_requests.http` — archivos vacíos

Ambos están trackeados en git con 0 bytes de contenido. Probablemente quedaron
de un `touch` que nunca se llenó.

**Qué hacer:** bórralos o complétalos. `tests_requests.http` en particular
suena a que la intención era tener una colección de requests HTTP de ejemplo
para probar la API a mano (útil, dado que no hay Postman collection ni nada
similar) — si te sirve, vale la pena llenarlo de verdad en vez de dejarlo como
placeholder.

### 4. `.vscode/` trackeado en git

`launch.json`, `settings.json`, `extensions.json` están commiteados. Es config
de tu editor personal, no del proyecto — si cambias de máquina o de preferencias
de VS Code, esos cambios van a aparecer como diffs de repo sin relación con el
código.

**Qué hacer:** `git rm -r --cached .vscode` y agregarlo a `.gitignore`.
Excepción razonable: si `extensions.json` recomienda extensiones a cualquiera
que abra el repo (Python, Pylance, etc.), ese archivo específico sí puede valer
la pena mantenerlo — pero `settings.json` y `launch.json` son personales.

---

## Qué mejorar (y cómo)

### 1. Duplicación de lógica de frontend entre tres archivos

`baseName`, `clockTime`/`fmtTime`, `humanGap`, `escapeHtml`/`esc`, y la función
que renderiza el detalle de una detección están reimplementadas por separado en
`console.js`, `tree.html`, e `incident.html` — mismas ~10-15 líneas escritas
tres veces, con nombres ligeramente distintos (`detectionDetailHtml` en
`tree.html` vs. `evidenceHtml`/`incidentHtml` en `console.js` vs.
`detectionCard` en `incident.html`). Es exactamente el tipo de duplicación que
te va a morder la próxima vez que arregles un bug de formato de fecha en un
lugar y se te olvide el otro.

**Cómo:** extraer un `frontend/static/common.js` con las funciones puras
(formateo de tiempo, escape de HTML, helpers de severidad) e importarlo con
`<script src="/static/common.js">` en los tres HTML. No hace falta un bundler —
son funciones globales simples, igual que ahora.

### 2. Duplicación entre los scripts de seed

`seed_apt.py`, `seed_rw.py`, y `seed_full_coverage.py` (1.313 líneas combinadas)
reimplementan cada uno sus propias versiones de `at()`, `proc()`, `raw_event()`,
y `events()` — los mismos helpers de construcción de eventos Sysmon sintéticos,
copiados con variaciones menores en cada archivo.

**Cómo:** un `scripts/_seed_common.py` con esos cuatro helpers, importado por
los tres (y por `seed_demo.py`, que ya tiene su propia versión reducida). Reduce
el mantenimiento de "si cambia el formato de un evento Sysmon, hay que tocar
cuatro archivos" a uno.

### 3. Versión desincronizada

`backend/main.py:105` declara `version="0.2.0"` en el `FastAPI(...)`, visible en
`/api/docs`. El README dice `v0.3.0`. Cualquiera que mire la documentación
interactiva de la API ve una versión vieja.

**Cómo:** una sola línea — actualizar `main.py:105` a `"0.3.0"`. Si quieres que
no vuelva a pasar, léela desde un solo lugar (por ejemplo `settings.app_version`
en `config.py`) y que tanto `main.py` como el README template se llenen desde ahí.

### 4. Inconsistencia de idioma en el código

Casi todo el código y los docstrings están en inglés — con una excepción: el
docstring de `ConnectionManager` en `backend/api/ws.py` ("Mantiene las sesiones
del dashboard y difunde detecciones en vivo.") está en español. Es un detalle
menor, pero salta si alguien lee el código de punta a punta.

**Cómo:** traducirlo al inglés para que sea consistente con el resto del código
(o, si prefieres, decidir conscientemente que el proyecto es bilingüe y dejarlo
— pero como está ahora parece un descuido, no una decisión).

### 5. `console.css` de 2.563 líneas en un solo archivo

No es un problema urgente, pero a este tamaño empieza a costar encontrar una
regla específica sin usar buscador. No hay comentarios de sección al principio
del archivo que sirvan de índice (aunque sí los hay dispersos).

**Cómo:** si sigue creciendo, dividir por área (`base.css`, `queue.css`,
`tree.css`, `search.css`) servidos como múltiples `<link>` — no hace falta build
step, el navegador cachea cada uno por separado igual que ahora.

### 6. El motor no puede expresar reglas que comparan dos campos entre sí

Confirmado en esta misma sesión de desarrollo: el matcher solo compara un campo
contra un valor literal esperado, nunca un campo contra otro campo del mismo
evento. Por eso SYS-092 (PE metadata masquerading) tuvo que resolverse con una
lista curada de binarios conocidos en vez de comparar dinámicamente
`OriginalFileName` contra el nombre real de `Image` — que sería la detección
genuina y generalizable (cualquier binario cuyo metadata interno no coincida
con su nombre de archivo, no solo los 12 de la lista).

**Cómo:** esto es la mejora de mayor impacto a la lógica de detección en sí, y
la más cara. Requiere extender la sintaxis de las reglas YAML con algo como
`field|matches_field: OtroCampo`, y el matcher para evaluarlo. Vale la pena si
piensas seguir agregando reglas de masquerading — cada una nueva hoy repite el
mismo patrón de "lista curada" en vez de resolver la clase de problema una vez.

### 7. Screenshots del README desactualizados (ya identificado, pendiente)

Ya lo habíamos visto: 5 de 6 capturas en `docs/` muestran "engine: 26 rules" (hoy
son 49) y no reflejan el dropdown de Set Verdict, el toggle de modo oscuro, ni
la vista Explore. Lo dejaste pausado a propósito para retomarlo con capturas
reales vía Brave — sigue siendo la mejora de mayor impacto visual pendiente.

---

## Priorización sugerida

Si tuviera que elegir por dónde empezar, en orden de impacto por esfuerzo:

1. **WAL en SQLite** (punto de "qué falta" #2) — cinco minutos, elimina una
   clase de bug que ya te costó tiempo real dos veces.
2. **Limpieza de sobras** (`backend/queue/`, los 4 `.jsonl`, los 2 archivos
   vacíos, `.vscode/`) — quince minutos, no cambia comportamiento, deja el repo
   legible para quien lo mire por primera vez (tu amigo, por ejemplo).
3. **Sincronizar versión** — un minuto.
4. **API key en `/admin/*`** — si en algún momento corres esto en algo más que
   tu laptop, esto deja de ser opcional.
5. **CI mínimo con pytest** — quince minutos, protege todo lo demás.
6. El resto (deduplicación de frontend/scripts, `.env.example`, LICENSE,
   screenshots nuevas) son mejoras de calidad de vida y de pulido — importantes,
   pero ninguna te va a morder si las dejas para después.
