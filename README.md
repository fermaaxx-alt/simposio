# Sistema de asistencia universitaria con QR dinámico

Aplicación web Flask + SQLite. Los docentes inician sesión y administran clases y listas. Los estudiantes **no crean cuentas ni inician sesión**: escanean el QR vigente, escriben su código estudiantil y marcan asistencia.

## Requisitos e instalación
- Python 3.10 o superior

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Configura una clave secreta privada antes de iniciar:
```powershell
# Windows PowerShell
$env:APP_SECRET="pon-aqui-una-clave-larga-y-aleatoria"
```
```bash
# macOS/Linux
export APP_SECRET="pon-aqui-una-clave-larga-y-aleatoria"
```

Crea la cuenta del docente:
```bash
flask --app app create-user
```
Cuando pregunte el rol, escribe `teacher`. Inicia el servidor:
```bash
flask --app app run --host 0.0.0.0 --port 5000
```
Abre `http://127.0.0.1:5000` en la computadora del docente.

## Uso
1. El docente inicia sesión y crea una clase.
2. En **Administrar estudiantes**, pega toda la lista en **Importar lista completa**. Usa un encabezado `SECCIÓN: 0901` y luego una línea por estudiante en formato `Nombre - número de cuenta`. El sistema crea las secciones y asigna cada estudiante automáticamente.
3. Inicia la asistencia y proyecta el QR.
4. Cada estudiante escanea el QR, escribe únicamente su número de cuenta y pulsa **Marcar asistencia**. El sistema identifica automáticamente su sección según la inscripción.
5. El docente ve los registros con su sección en tiempo real y puede abrir **Ver reporte** para consultar o filtrar la asistencia por sección.

No se crea una contraseña ni una cuenta que el estudiante tenga que administrar. Los códigos deben ser únicos y comunicarse únicamente a su titular.

## Red y seguridad
Para escanear desde los teléfonos, estos deben poder acceder al servidor mediante una dirección de red alcanzable; no uses `localhost` en el teléfono. El QR rota cada 15 segundos y se valida la inscripción y que no exista un registro duplicado. Aun así, un QR dinámico no demuestra por sí solo que el estudiante esté físicamente en el aula: el enlace podría compartirse mientras siga vigente.

Antes de producción, usa HTTPS, servidor WSGI de producción, `APP_SECRET` aleatoria, protección CSRF, límites de intentos, copias de seguridad y revisión de privacidad/seguridad. No expongas el servidor de desarrollo directamente a Internet.

## Secciones y compatibilidad
Las clases nuevas se crean con una sección inicial llamada **General**, que puedes conservar o complementar con otras. En bases de datos existentes, las inscripciones anteriores se asignan automáticamente a **General** para no perder datos. Las asistencias anteriores reciben la sección de inscripción correspondiente.

## Importación masiva
Ejemplo de texto para pegar:
```
SECCIÓN: 0901
Ana López - 20241001
Pedro Díaz - 20241002

SECCIÓN: 0902
María Ruiz - 20241003
Carlos Pérez - 20241004
```
También se aceptan líneas con los campos separados por coma, punto y coma o tabulación. Si una cuenta ya está inscrita en esta clase, se actualiza su nombre/sección en lugar de duplicarla. Si el texto contiene errores de formato, no se importa parcialmente.
