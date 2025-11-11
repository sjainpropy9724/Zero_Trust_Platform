from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential, PublicKeyCredentialDescriptor
from webauthn.helpers.exceptions import InvalidAuthenticationResponse 
from sqlalchemy.orm import Session
from app.db import models

RP_ID = "localhost"  # Relying Party ID
RP_NAME = "Zero-Trust Platform"
ORIGIN = "http://localhost:8000" # The origin of your frontend

def get_registration_options(username: str):
    """Generate challenges for a new user registration."""
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=username,
        user_id=username.encode("utf-8"),
    )
    return options

def verify_registration(credential: dict, challenge: str, db: Session, username: str):
    """Verify the registration response and create a new user."""
    try:
        registration_verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True,
        )

        # Check if a user with this credential ID already exists
        db_user_by_cred_id = db.query(models.User).filter(
            models.User.passkey_credential_id == registration_verification.credential_id
        ).first()

        if db_user_by_cred_id:
            return None 

        # Create new user
        new_user = models.User(
            username=username,
            passkey_credential_id=registration_verification.credential_id,
            passkey_public_key=registration_verification.credential_public_key,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return new_user
    except Exception as e:
        print(f"Registration verification failed: {e}")
        return None

def get_authentication_options(user: models.User):
    """Generate challenges for an existing user login."""
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=user.passkey_credential_id)
        ],
    )
    return options

def verify_authentication(
    user: models.User, 
    credential: dict,
    challenge: str
):
    """Verify the authentication response and return the user if valid."""
    try:
        auth_verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=user.passkey_public_key,
            credential_current_sign_count=0, 
            require_user_verification=True,
        )
        

        return user
    except InvalidAuthenticationResponse as e:
        print(f"Authentication verification failed: {e}")
        return None