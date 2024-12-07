from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from routers import users

app = FastAPI()

origins = ["http://localhost:4200"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir el router para las rutas de usuarios
app.include_router(users.router)

@app.get("/")
def root():
    return {"message": "API funcionando correctamente"}

