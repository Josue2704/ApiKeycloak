from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from jose import jwt, JWTError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from configuracion import settings

router = APIRouter()

# Configuración de la base de datos
DATABASE_URL = settings.database_url
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Keycloak Public Key
KEYCLOAK_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA35w7XQGyZN2Q4WC650NgFu4HKEJZT6528fcMDCEm1eI+jiNaWuosw1h+WdLJuJ7lbHUjfY7LuuqEugzKn4Df8ODperM1qr9PRdTLoHyUTFJs+MJdOY1+63CFa2SWtSvztjsWhroh6KHRzqSNIPIZQEn7IUY/qbG24i7MdUVke7+0UXgzZjAcKGTp6KMCD6mvAurzFCs4+kInh/78xTrghsbjSEyDFR965gqfErwwFRZ/3CIAN75dITXdIj6t2/vOYg5NSRvPMWDXydFmzVivm1JodY6FCNfHQUtQC8p884aK0LvC6QS5uwhS7wCwuj35ocGLmfhhV+H04RKo1sIg8wIDAQAB
-----END PUBLIC KEY-----
"""

# Modelo para los datos del usuario
class AdditionalUserData(BaseModel):
    Documento: str
    Tipo_Usuario: str  # 'empresa' o 'desarrollador'
    Perfil: str = None  # Opcional

# Crear una función para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Decodificar el token
def decode_token(token: str):
    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=["RS256"], audience="fastapi-client")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Endpoint para completar el registro
@router.post("/complete-registration")
def complete_registration(
    user_data: AdditionalUserData,
    authorization: str = Header(...),  # Capturamos el token desde el header
    db: Session = Depends(get_db)      # Usamos la dependencia limpia
):
    # Extraer el token del header y decodificarlo
    token = authorization.replace("Bearer ", "")
    token_data = decode_token(token)

    # Extraer datos del token
    email = token_data.get("email")
    firstname = token_data.get("given_name")
    lastname = token_data.get("family_name")
    keycloak_id = token_data.get("sub")

    # Validar que todos los datos necesarios estén presentes
    if not all([email, firstname, lastname, keycloak_id]):
        raise HTTPException(status_code=400, detail="Faltan datos en el token")

    # Insertar en la base de datos
    query = text("""
        INSERT INTO Usuarios (Nombre, Correo, Documento, Keycloak_id, Tipo_Usuario, Perfil)
        VALUES (:nombre, :correo, :documento, :keycloak_id, :tipo_usuario, :perfil)
    """)
    try:
        db.execute(query, {
            "nombre": f"{firstname} {lastname}",
            "correo": email,
            "documento": user_data.Documento,
            "keycloak_id": keycloak_id,
            "tipo_usuario": user_data.Tipo_Usuario,
            "perfil": user_data.Perfil,
        })
        db.commit()
        return {"message": "Registro completado exitosamente"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al registrar usuario: {str(e)}")

@router.get("/verify-admin")
def verify_admin(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    token = authorization.replace("Bearer ", "")
    token_data = decode_token(token)

    keycloak_id = token_data.get("sub")
    if not keycloak_id:
        raise HTTPException(status_code=401, detail="Token inválido: falta el Keycloak ID")

    query = text("""
        SELECT Tipo_Usuario 
        FROM Usuarios 
        WHERE Keycloak_id = :keycloak_id
    """)
    result = db.execute(query, {"keycloak_id": keycloak_id}).mappings().fetchone()

    if not result:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    tipo_usuario = result["Tipo_Usuario"]  # Ahora accedemos como diccionario
    if tipo_usuario != "administrador":
        raise HTTPException(status_code=403, detail="Acceso denegado: usuario no autorizado")

    return {"message": "Usuario autenticado como administrador"}

@router.get("/usuarios")
def listar_usuarios(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    token = authorization.replace("Bearer ", "")
    token_data = decode_token(token)

    # Opcionalmente verificar si es admin
    keycloak_id = token_data.get("sub")
    if not keycloak_id:
        raise HTTPException(status_code=401, detail="Token inválido")

    # Consulta todos los usuarios
    query = text("SELECT Usuario_id, Nombre, Correo, Documento, Tipo_Usuario, Estado FROM Usuarios")
    result = db.execute(query).mappings().all()

    usuarios = [dict(row) for row in result]
    return {"usuarios": usuarios}
