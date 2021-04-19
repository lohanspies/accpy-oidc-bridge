'''OIDC server example'''
# import datetime
import time
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.sqlite import JSON, BOOLEAN, DATETIME
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin
)
from src.database import Base, db


import uuid
import os

class User(Base):  # pylint: disable=R0903
    '''User class example'''

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(100), unique=True)

    def get_user_id(self):
        '''Fetch user identifier'''
        return self.id


class OAuth2Client(Base, OAuth2ClientMixin):
    '''OAuth2Client class example'''

    __tablename__ = 'oauth2_client'

    id = Column(Integer, primary_key=True)


class OAuth2AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):
    '''OAuth2AuthorizationCode class example'''

    __tablename__ = 'oauth2_code'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    user = relationship('User')

    def is_expired(self):
        return self.auth_time + 300 < time.time()


class OAuth2Token(Base, OAuth2TokenMixin):
    '''OAuth2Token class example'''

    __tablename__ = 'oauth2_token'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    user = relationship('User')

    def is_refresh_token_active(self):
        '''Check if refresh token is active'''
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()

def disambiguate_referent(referent: str) -> str:
    ref_idx = 1
    ref_split = referent.split("~")
    if len(ref_split) > 1:
        old_idx = int(ref_split[-1])
        ref_idx += old_idx

    return f"{ref_split[0]}~{ref_idx}"

class PresentationConfigurations(Base):
    '''Presentation Configuration class example'''

    __tablename__ = 'presentation_configs'

    id = Column(String(100), primary_key=True)
    subject_identifier = Column(String(100))
    configuration = Column(JSON)

    def get_presentation_id(self):
        '''Fetch presentation config identifier'''
        return self.id

    def __str__(self):
        return f"{self.id}"

    def to_json(self):
        presentation_request = {
            "name": self.configuration.get("name", ""),
            "version": self.configuration.get("version", ""),
            "requested_attributes": {},
            "requested_predicates": {},
        }

        for attr in self.configuration.get("requested_attributes", []):
            label = attr.get("label", str(uuid.uuid4()))
            if label in presentation_request.get("requested_attributes", {}).keys():
                label = disambiguate_referent(label)
            presentation_request["requested_attributes"].update({label: attr})

        for attr in self.configuration.get("requested_predicates", []):
            label = attr.get("label", str(uuid.uuid4()))
            if label in presentation_request.get("requested_predicates", {}).keys():
                label = disambiguate_referent(label)

            presentation_request["requested_predicates"].update({label: attr})

        return {"proof_request": presentation_request}

# class AuthSession(TimeStampedModel):
class AuthSession(Base):
    '''AuthSession class example'''

    __tablename__ = 'authsession'

    id = Column(String, primary_key=True, unique=True, default=uuid.uuid4())
    presentation_record_id = Column(String(100))
    presentation_request_id = Column(String(100))
    presentation_request = Column(JSON)
    presentation_request_satisfied = Column(BOOLEAN)
    expired_timestamp = Column(DATETIME)
    request_parameters = Column(JSON)
    presentation = Column(JSON)

    def __str__(self):
        return f"{self.presentation_record_id} - {self.presentation_request_id}"

    def satisfy_session(self, presentation):
        self.presentation_request_satisfied = True
        self.presentation = presentation
        self.save()


# class MappedUrl(TimeStampedModel):
class MappedUrl(Base):
    '''Mapped URL class example'''

    __tablename__ = 'mapped_url'

    id = Column(String(100), primary_key=True, default=uuid.uuid4)
    url = Column(String(100))#models.TextField()
    session = Column(Integer, ForeignKey('authsession.id', ondelete='CASCADE'))

    def __str__(self):
        return f"{self.id}"

    def get_short_url(self):
        SITE_URL = os.getenv('SITE_URL')
        return f"{SITE_URL}/url/{self.id}"
        # TODO - fix env/app variables and import from there.
        # return f"http://localhost:8000/url/{self.id}"
