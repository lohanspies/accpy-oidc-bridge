'''OIDC server example'''
# import requests
from fastapi import FastAPI, Request, Response
# from fastapi.params import Depends
from fastapi.responses import JSONResponse
from mangum import Mangum
from starlette.exceptions import HTTPException as StarletteHTTPException
from src.routes import router
from src.database import Base, engine
from src.oauth2 import config_oauth
# from src.database import SessionLocal
# from fastapi.security import OAuth2AuthorizationCodeBearer, OpenIdConnect
# from app.core.config import settings
# from pydantic import BaseSettings
# from . import config
from starlette.middleware.sessions import SessionMiddleware
import os

# class Settings(BaseSettings):
#     app_name: str = "Awesome API"
#     admin_email: str
#     items_per_user: int = 50
#
#
# settings = Settings()

# oauth2_scheme = OAuth2AuthorizationCodeBearer(
#     authorizationUrl=settings.AUTHORIZATION_URL,
#     tokenUrl=settings.TOKEN_URL
# )

# oauth2_scheme = OAuth2AuthorizationCodeBearer(
#     authorizationUrl='/',
#     tokenUrl='/'
# )

# app = FastAPI(
#     title=settings.PROJECT_NAME,
#     openapi_url=f"{settings.API_V1_STR}/openapi.json",
#     swagger_ui_init_oauth={
#         "usePkceWithAuthorizationCodeGrant": True,
#         "clientId": settings.CLIENT_ID,
#         "scopes": settings.OAUTH_SCOPES,
#     },
# )

# app = FastAPI(
#     title="TEST",
#     openapi_url=f"/localhost:5000/openapi.json",
#     swagger_ui_init_oauth={
#         "usePkceWithAuthorizationCodeGrant": True,
#         "clientId": 'D3JlWRV57SjsiFR52stiEBrM',
#         "scopes": "openid profile",
#     },
# )

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="secret", session_cookie="cookie22")

# Get environment variables
SITE_URL = os.getenv('SITE_URL')
print('SITE URL ', SITE_URL)
PASSWORD = os.environ.get('API_PASSWORD')

app.config = {
    'SITE_URL': {SITE_URL},
    'OAUTH2_JWT_ISS': 'https://authlib.org',
    'OAUTH2_JWT_KEY': 'secret-key',
    'OAUTH2_JWT_ALG': 'HS256',
    'OAUTH2_TOKEN_EXPIRES_IN': {
        'authorization_code': 300
    },
    'OAUTH2_ERROR_URIS': [
        ('invalid_client', 'https://developer.your-company.com/errors#invalid-client'),
    ]
}

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    '''Override the StarletteHTTPException exception'''
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )

Base.metadata.create_all(bind=engine)

config_oauth(app)

app.include_router(router)


# app.include_router(router, dependencies=[Depends(oauth2_scheme)])

handler = Mangum(app)
