# SIGA - Lab Vulnerable de Ciberseguridad

Portal académico (ficticio) **intencionalmente vulnerable**, hecho en
Flask, para el trabajo de "Técnicas de explotación y defensa en
aplicativos Web".

⚠️ **Uso local únicamente.** No la despliegues en un servidor accesible
desde internet ni en una red compartida sin controlar quién la ve.

## Instalación

```bash
cd vulnapp
python3 -m venv venv
source venv/bin/activate        # en Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

Abre `http://127.0.0.1:5000`.

Usuarios de prueba:
| Usuario | Password | Rol |
|---|---|---|
| jperez | juliana123 | estudiante (id=1) |
| crodrig | camilo456 | estudiante (id=2) |
| admin | S3cr3tPass! | admin (id=3) |

## Vulnerabilidades incluidas

### 1. SQL Injection — `/login`

**Causa:** el usuario y la contraseña se insertan directamente en la
query SQL con un f-string, en vez de usar parámetros.

**Explotación (bypass de autenticación):**
- Usuario: `admin' --`
- Contraseña: (lo que sea, no importa)

La query resultante queda:
```sql
SELECT * FROM usuarios WHERE usuario = 'admin' --' AND password = '...'
```
El `--` comenta el resto, así que la comparación de contraseña nunca se
evalúa y entras como `admin` sin conocer la clave real.

**Mitigación:**
- Usar **consultas parametrizadas / prepared statements** (`?` en
  sqlite3) — nunca concatenar input.
- Hashear contraseñas (bcrypt/argon2), nunca guardarlas en texto plano.
- No mostrar errores de base de datos crudos al usuario.

### 2. Cross-Site Scripting (XSS)

**2a. Reflejado — `/buscar?q=...`**

**Causa:** el parámetro `q` se inserta en el HTML de la respuesta sin
escapar (se construye el HTML a mano con `render_template_string` en
vez de usar el autoescape normal de Jinja2).

**Explotación:**
```
http://127.0.0.1:5000/buscar?q=<script>alert(document.cookie)</script>
```

**2b. Almacenado — `/foro`**

**Causa:** el mensaje se guarda tal cual en la base de datos y se
renderiza con el filtro `| safe`, que desactiva el escape automático.

**Explotación:** publica en "Mensaje":
```html
<img src=x onerror=alert('XSS-almacenado')>
```
Cada usuario que visite `/foro` después ejecutará ese script en su
navegador.

**Mitigación:**
- Dejar que Jinja2 escape automáticamente (`{{ variable }}`, nunca
  `{{ variable | safe }}` con contenido de usuario).
- Content-Security-Policy (CSP) como capa adicional.
- Si necesitas permitir HTML limitado, sanitizar con `bleach` y lista
  blanca de tags.

### 3. IDOR (Broken Access Control) — `/notas/<id>`

**Causa:** la ruta solo verifica que haya una sesión iniciada, pero
nunca valida que el `id` solicitado sea el del usuario en sesión (o que
el usuario en sesión sea admin).

**Explotación:**
1. Inicia sesión como `jperez` (id=1).
2. Ve tu propio boletín en `/notas/1`.
3. Cambia la URL a `/notas/2` o `/notas/3` y verás las calificaciones de
   `crodrig` o del `admin` sin ninguna autorización.

**Mitigación:**
```python
if estudiante_id != session["usuario_id"] and not session.get("es_admin"):
    return "No autorizado", 403
```
Nunca confiar en un ID recibido del cliente sin comparar contra el
dueño real del recurso (verificación de propiedad / control de acceso
a nivel de objeto).

## Herramientas para probar/documentar el laboratorio

- **Burp Suite** para interceptar y modificar requests.
- `curl` para reproducir el bypass de SQLi por línea de comandos:
  ```bash
  curl -d "usuario=admin' --&password=x" http://127.0.0.1:5000/login
  ```
- El navegador con DevTools para ver el XSS ejecutándose.

## Estructura del proyecto

```
vulnapp/
├── app.py                     # rutas y lógica (vulnerabilidades comentadas)
├── requirements.txt
├── static/css/style.css
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html             # SQLi
│   ├── foro.html              # XSS almacenado
│   ├── mis_notas.html         # boletín propio
│   └── notas_detail.html      # IDOR
└── lab.db                     # se crea sola al ejecutar (SQLite)
```
