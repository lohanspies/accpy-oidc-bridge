'''OIDC server example'''

import time

import requests
from authlib.oauth2 import OAuth2Error
from fastapi import APIRouter, Request, Form, status, HTTPException
from fastapi.params import Depends
from fastapi.responses import RedirectResponse, Response, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from werkzeug.security import gen_salt
from src.oauth2 import authorization, require_oauth, generate_user_info
from src.database import db
from src.models import User, OAuth2Client
from src.utils.token import token
from src.utils.shortener import create_short_url
from src.endpoints.token import create_id_token
from src.models import MappedUrl, AuthSession, PresentationConfigurations
from src.endpoints.authorize import authorization_vc
# from oidcservice.oauth2.authorization import Authorization
# from oidcservice.oidc.authorization import Authorization

import qrcode
from qrcode.image.svg import SvgImage
from lxml import etree

import json
import logging

#TODO - fix logging configuration for app
# from .config import Settings, get_setting

LOGGER = logging.getLogger(__name__)

router = APIRouter()

templates = Jinja2Templates(directory='src/templates')

# @router.get('/test')
# def get_param_list(config: Settings = Depends(get_setting)):
#     return config

@router.get('/')
def home(request: Request):
    '''List all clients'''
    clients = db.query(OAuth2Client).all()  # pylint: disable=E1101
    return templates.TemplateResponse('home.html', {'request': request, 'clients': clients})

@router.get('/create_client', tags=['OAUTH 2 Client'])
def get_create_client(request: Request):
    '''Display form to create client'''
    return templates.TemplateResponse('create_client.html', {'request': request})


@router.post('/create_client', tags=['OAUTH 2 Client'])
def post_create_client(  # pylint: disable=R0913
        client_name: str = Form(...),
        client_uri: str = Form(...),
        grant_type: str = Form(...),
        redirect_uri: str = Form(...),
        response_type: str = Form(...),
        scope: str = Form(...),
        token_endpoint_auth_method: str = Form(...)):

    '''Create the client information'''
    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at
    )

    client_metadata = {
        'client_name': client_name,
        'client_uri': client_uri,
        'grant_types': grant_type.splitlines(),
        'redirect_uris': redirect_uri.splitlines(),
        'response_types': response_type.splitlines(),
        'scope': scope,
        'token_endpoint_auth_method': token_endpoint_auth_method
    }
    client.set_client_metadata(client_metadata)

    if token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.add(client)  # pylint: disable=E1101
    db.commit()  # pylint: disable=E1101

    return RedirectResponse(url='/', status_code=status.HTTP_303_SEE_OTHER)


@router.post('/oauth/authorize', tags=['OAUTH 2'])
def authorize(
        request: Request,
        uuid: str = Form(...)):
    '''Provide authorization code response'''
    user = db.query(User).filter(User.uuid == uuid).first()  # pylint: disable=E1101

    if not user:
        user = User(uuid=uuid)
        db.add(user)  # pylint: disable=E1101
        db.commit()  # pylint: disable=E1101

    request.body = {
        'uuid': uuid
    }

    try:
        authorization.validate_consent_request(request=request, end_user=user)
    except OAuth2Error as error:
        return dict(error.get_body())

    return authorization.create_authorization_response(request=request, grant_user=user)


@router.post('/oauth/token', tags=['OAUTH 2'])
def token(
        request: Request,
        grant_type: str = Form(...),
        scope: str = Form(None),
        code: str = Form(None),
        refresh_token: str = Form(None),
        code_verifier: str = Form(None),
        client_id: str = Form(None),
        client_secret: str = Form(None)):
    '''Exchange the authorization code to access token'''
    request.body = {
        'grant_type': grant_type,
        'scope': scope,
    }
    if grant_type == 'authorization_code':
        request.body['code'] = code
    elif grant_type == 'refresh_token':
        request.body['refresh_token'] = refresh_token

    if code_verifier:
        request.body['code_verifier'] = code_verifier

    if client_id:
        request.body['client_id'] = client_id

    if client_secret:
        request.body['client_secret'] = client_secret

    return authorization.create_token_response(request=request)


@router.post('/oauth/introspect', tags=['OAUTH 2'])
def introspect_token(
        request: Request,
        token: str = Form(...),  # pylint: disable=W0621
        token_type_hint: str = Form(...)):
    '''Introspect the token using access token'''
    request.body = {}

    if token:
        request.body.update({'token': token})

    if token_type_hint:
        request.body.update({'token_type_hint': token_type_hint})

    return authorization.create_endpoint_response('introspection', request=request)


@router.post('/oauth/revoke', tags=['OAUTH 2'])
def revoke_token(
        request: Request,
        token: str = Form(...),  # pylint: disable=W0621
        token_type_hint: str = Form(...)):
    '''Revoke the token using access token'''
    request.body = {}

    if token:
        request.body.update({'token': token})

    if token_type_hint:
        request.body.update({'token_type_hint': token_type_hint})

    return authorization.create_endpoint_response('revocation', request=request)


@router.get('/oauth/userinfo', tags=['OAUTH 2'])
def userinfo(request: Request):
    '''Request user profile information'''
    with require_oauth.acquire(request, 'profile') as token:  # pylint: disable=W0621
        return generate_user_info(token.user, token.scope)

@router.post('/webhooks', tags=['OIDC'])
def webhooks(request: Request, topic, response: Response):
    # TODO: validate 'secret' key
    message = json.loads(request.body)

    LOGGER.info(f"webhook received - topic: {topic} and message: {message}")
    # Should be triggered after a proof request has been sent by the org
    if topic == "present_proof":
        state = message["state"]
        if state != "presentation_received":
            LOGGER.info(f"Presentation Request not yet received, state is [{state}]")
            return response

        presentation_exchange_id = "- not_set -"
        try:
            proof = message["presentation"]["requested_proof"]
            presentation_exchange_id = message["presentation_exchange_id"]

            LOGGER.info(f"Proof received: {proof}")

            session = AuthSession.objects.get(
                presentation_request_id=presentation_exchange_id
            )
            session.satisfy_session(proof)

        except (AuthSession.DoesNotExist, AuthSession.MultipleObjectsReturned):
            LOGGER.warning(
                f"Could not find a corresponding auth session to satisfy. "
                f"Presentation request id: [{presentation_exchange_id}]"
            )
            return response

        except Exception as e:
            LOGGER.error(f"Wrong 'present_proof' body: {message} - error: {e}")
            return response

    return response

@router.get('/url/{id}', tags=['OIDC'])
def url_shortener(request: Request, id: str, response: Response):
    print('IN URL ENDPOINT WITH VAR ', id)
    try:
        mapped_url = db.query(MappedUrl).filter(MappedUrl.id == id).all()
        print('MAPPED URL ID ', mapped_url[0].id)
        print('MAPPED URL RETRIEVED ', mapped_url[0].url)
        print('MAPPED URL SESSION ', mapped_url[0].session)
        return RedirectResponse(mapped_url[0].url)
    except Exception:
        #TODO - change all exception status codes to be HTTPExceptions with error codes
        response.status_code = status.HTTP_400_BAD_REQUEST  # ("Wrong key provided")
        return response

@router.get('/vc/connect/poll', tags=['OIDC'])
def poll(request: Request, response: Response):
    presentation_request_id = request.get("pid")
    if not presentation_request_id:
        response.status_code = status.HTTP_404_NOT_FOUND
        return response

    session = get_object_or_404(
        AuthSession, presentation_request_id=presentation_request_id
    )

    if not session.presentation_request_satisfied:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response

    return response

@router.post('/vc/connect/callback', tags=['OIDC'])
def callback(request: Request, response: Response):
    presentation_request_id = request.GET.get("pid")
    if not presentation_request_id:
        response.status_code = status.HTTP_404_NOT_FOUND
        return response

    session = get_object_or_404(
        AuthSession, presentation_request_id=presentation_request_id
    )

    if not session.presentation_request_satisfied:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response

    if session.request_parameters.get("response_type", "") == "code":
        redirect_uri = session.request_parameters.get("redirect_uri", "")
        url = f"{redirect_uri}?code={session.pk}"
        state = session.request_parameters.get("state")
        if state:
            url += f"&state={state}"
        return RedirectResponse(url)
    response.status_code = status.HTTP_400_BAD_REQUEST
    return response

@router.get('/vc/connect/token', tags=['OIDC'])
def token_endpoint(request: Request, response: Response):
    message = json.loads(request.body)
    grant_type = message.get("grant_type")
    if not grant_type or grant_type != "authorization_code":
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response

    session_id = message.get("code")
    if not session_id:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response

    session = get_object_or_404(AuthSession, id=session_id)

    if not session.presentation_request_satisfied:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response

    try:
        token = create_id_token(session)
        session.delete()
    except Exception as e:
        LOGGER.warning(f"Error creating token for {session_id}: {e}")
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return response

    # Add CorsOrigin with cors_allow_any?

    data = {"access_token": "invalid", "id_token": token, "token_type": "Bearer"}
    return JSONResponse(data)

@router.get('/vc/connect/authorize', tags=['OIDC'], response_class=HTMLResponse)
async def authorize(request: Request, response: Response, client_id: str, pres_req_conf_id: str, uuid: str, scope: str, response_type: str, redirect_uri: str, state: str, nonce: str):
    '''Provide authorization code response'''
    user = db.query(User).filter(User.uuid == uuid).first()  # pylint: disable=E1101

    if not user:
        user = User(uuid=uuid)
        db.add(user)  # pylint: disable=E1101
        db.commit()  # pylint: disable=E1101

    request.body = {
        'uuid': uuid
    }

    pres_req_conf_id = request.query_params.get("pres_req_conf_id")
    print('Presentation Request ID ', pres_req_conf_id)
    if not pres_req_conf_id:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response#("pres_req_conf_id query parameter not found")

    presentation_configuration = db.query(PresentationConfigurations).filter(
        PresentationConfigurations.id == pres_req_conf_id).all()

    print('Presentation Configuration ', presentation_configuration)

    scopes = request.query_params.get("scope")
    print('Scopes ',scopes)
    if not scopes or "vc_authn" not in scopes.split(" "):
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response#("Scope vc_authn not found")

    try:
        print('Request Body ', request.body)
        print('Request Query Params ', request.query_params)
        print('Request Headers ', request.headers)
        authorization.validate_consent_request(request=request, end_user=user)
        print('CONSENT REQUEST VALIDATED')
    except OAuth2Error as error:
        return dict(error.get_body())
    print('VALIDATION DONE')

    short_url, session_id, pres_req, b64_presentation = await authorization_vc(pres_req_conf_id, request.query_params.__str__())
    print('PRES REQ ', pres_req)
    print('B64 PRESENTATION ', b64_presentation)

    request.session["sessionid"] = session_id
    print('SESSION ', request.session["sessionid"])

    result =  authorization.create_authorization_response(request=request, grant_user=user)
    print('AUTHORISATION RESPONSE', result)
    # Create QR Code
    # TODO - remove static variables
    img_short_url = qrcode.make('http://localhost:8000/url' + pres_req, image_factory=SvgImage)
    img_base64_url = qrcode.make('http://localhost:8000?m=' + b64_presentation, image_factory=SvgImage)

    rendered_svg_short_url = etree.tostring(img_short_url.get_image()).decode()
    rendered_svg_base64_url = etree.tostring(img_base64_url.get_image()).decode()

    # TODO - remove static variables
    return templates.TemplateResponse('qr_display.html', {'request': request, "b64_presentation": b64_presentation, "poll_interval": 5000, "poll_max_tries": 12, "poll_url": f"http://localhost:8000/vc/connect/poll?pid={pres_req}", "resolution_url": f"ttp://localhost:8000/vc/connect/callback?pid={pres_req}","pres_req": pres_req,"rendered_svg_short_url": rendered_svg_short_url, "rendered_svg_base64_url": rendered_svg_base64_url })

@router.get('/api/vc-configs/', status_code=status.HTTP_200_OK, tags=['Verifiable Credential Presentation Configuration'])
async def vc_configs(request: Request, response: Response):
    presentation_configuration = db.query(PresentationConfigurations).all()
    print('presentation_configuration ', presentation_configuration)
    return presentation_configuration

@router.post('/api/vc-configs/', tags=['Verifiable Credential Presentation Configuration'])
async def vc_configs(request: Request, response: Response, id: str = Form(...),
        subject_identifier: str = Form(...),
        configuration: str = Form(...)):
    presentation_config = PresentationConfigurations(id=id, subject_identifier=subject_identifier,
                                                     configuration=configuration)
    print('presentation_config ',presentation_config)
    db.add(presentation_config)
    db.commit()
    return presentation_config

@router.put('/api/vc-configs/', tags=['Verifiable Credential Presentation Configuration'])
# TODO - Fix Update API for Presentation Configurations. Not working at the moment.
async def vc_configs(request: Request, response: Response, id: str = Form(...),
        subject_identifier: str = Form(...),
        configuration: str = Form(...)):
    presentation_config_record = db.query(PresentationConfigurations).filter(PresentationConfigurations.id == id)

    if not presentation_config_record.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Presentation Config with id {id} not found")

    presentation_config = PresentationConfigurations(id=id, subject_identifier=subject_identifier,
                                                     configuration=configuration)
    print('DEBUG ', request.body().__str__(), request.headers, request.query_params)
    presentation_config_record.update(request)
    db.commit()
    return 'updated'

@router.delete('/api/vc-configs/', tags=['Verifiable Credential Presentation Configuration'])
async def vc_configs(request: Request, response: Response, id: str = Form(...)):
    presentation_config = db.query(PresentationConfigurations).filter(PresentationConfigurations.id == id)

    if not presentation_config.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Presentation Config with id {id} not found")

    presentation_config.delete(synchronize_session=False)
    db.commit()
    return 'done'



