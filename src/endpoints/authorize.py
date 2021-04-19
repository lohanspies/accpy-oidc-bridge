import uuid

from aries_cloudcontroller.aries_controller import AriesAgentController
from src.utils.shortener import create_short_url
from src.models import AuthSession, PresentationConfigurations, MappedUrl
from src.models import PresentationConfigurations
from datetime import datetime, timedelta
from src.utils.acapy_models import PresentationFactory
from src.database import db
import os

# TODO - replace AcaPy args with FastAPI.settings module

ACA_PY_URL = 'http://aca-py:5678'
print('ACAPY_URL ', ACA_PY_URL)
ACA_PY_TRANSPORT_URL = os.getenv('NGROK_AGENT_URL')#'http://0.0.0.0:5679'
print('ACAPY_TRANSPORT_URL ', ACA_PY_TRANSPORT_URL)

async def authorization_vc(pres_req_conf_id: str, request_parameters: dict):
    # TODO - replace AcaPy args with FastAPI.settings module
    # agent_controller = AriesAgentController(admin_url=settings.ACA_PY_URL)
    agent_controller = AriesAgentController(admin_url=ACA_PY_URL)
    # TODO - fix database storage and recovery of pres_req_conf_id
    presentation_configuration = db.query(PresentationConfigurations).filter(PresentationConfigurations.id == pres_req_conf_id).first()
    print('presentation_configuration ', presentation_configuration.to_json())

    response = await agent_controller.proofs.create_request(presentation_configuration.to_json())
    print('PROOF CREATE', response)
    public_did = await agent_controller.wallet.get_public_did()
    print('DID', public_did)
    endpoint = await agent_controller.ledger.get_did_endpoint(public_did['result']['did'])
    print('ENDPOINT', endpoint)
    # TODO - this will wail due to no TAA accepted on ledger
    TAA_response = await agent_controller.ledger.get_taa()
    TAA = TAA_response['result']['taa_record']
    TAA['mechanism'] = "service_agreement"
    # print(TAA)

    TAA_accept = await agent_controller.ledger.accept_taa(TAA)
    ## Will return {} if successful
    print(TAA_accept)
    # TODO - replace AcaPy args with FastAPI.settings module
    # await agent_controller.wallet.set_did_endpoint(public_did['did'], settings.ACA_PY_TRANSPORT_URL, 'Endpoint')
    await agent_controller.wallet.set_did_endpoint(public_did['result']['did'], ACA_PY_TRANSPORT_URL, 'Endpoint')
    endpoint = await agent_controller.ledger.get_did_endpoint(public_did['result']['did'])
    endpoint = endpoint['endpoint']
    print('ENDPOINT ', endpoint)
    print('VERKEY ', [public_did['result']['verkey']] )

    presentation_request = PresentationFactory.from_params(
        presentation_request=response.get("presentation_request"),
        p_id=response.get("thread_id"),
        verkey=[public_did['result']['verkey']],
        endpoint=endpoint,
    ).to_json()

    print('PROOF REQUEST ', presentation_request)

    presentation_request_id = response["presentation_exchange_id"]

    print('PRESENTATION REQUEST ID ', presentation_request_id)
    print('REQUEST PARAMETERS ', request_parameters)
    session = AuthSession(
        id=str(uuid.uuid4()),
        presentation_record_id=pres_req_conf_id,
        presentation_request_id=presentation_request_id,
        presentation_request=presentation_request,
        request_parameters=request_parameters,
        expired_timestamp=datetime.now() + timedelta(minutes=60),
    )
    print('SESSION ', session)
    db.add(session)
    db.commit()
    db.refresh(session)
    print('SESSION ',session.id)

    url, b64_presentation = create_short_url(presentation_request)
    print('URL ', url)

    id = str(uuid.uuid4())
    print('ID ', id)
    mapped_url = MappedUrl(id=id, url=url, session=session.id)
    db.add(mapped_url)
    db.commit()
    db.refresh(mapped_url)
    print('MAPPED URL ', mapped_url, id)
    # return presentation_config
    short_url = mapped_url.get_short_url()
    print('SHORT_URL ',short_url)

    # Terminate controller
    await agent_controller.terminate()

    return short_url, str(session.id), presentation_request_id, b64_presentation
