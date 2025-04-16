# hubspot.py

import json
import secrets
import base64
import urllib.parse
import httpx
import asyncio
import requests
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse

from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

CLIENT_ID = "3f2a589e-519f-4631-af50-6c0113ddcc0e"
CLIENT_SECRET = "65de038e-4dda-4c3b-9f72-bb43d9189429"
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"

AUTH_URL = "https://app.hubspot.com/oauth/authorize"
TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"
SCOPES = "crm.objects.companies.read"


async def authorize_hubspot(user_id, org_id):
    # Create a secure state with user and org information
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id
    }

    # Encode state for secure transmission
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    # Store state in Redis for verification during callback
    await add_key_value_redis(f"hubspot_state:{org_id}:{user_id}", json.dumps(state_data), expire=600)

    # Create code verifier for PKCE (if needed)
    code_verifier = secrets.token_urlsafe(32)
    await add_key_value_redis(f"hubspot_verifier:{org_id}:{user_id}", code_verifier, expire=600)

    # Build authorization URL
    query_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": encoded_state
    }

    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(query_params)}"
    return auth_url


async def oauth2callback_hubspot(request: Request):
    # Check for errors in the callback
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))

    # Get code and state from the request
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')

    # Decode the state
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    # Extract information from state
    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    # Get saved state and verifier from Redis
    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f"hubspot_state:{org_id}:{user_id}"),
        get_value_redis(f"hubspot_verifier:{org_id}:{user_id}"),
    )

    # Verify state
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                TOKEN_URL,
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f"hubspot_state:{org_id}:{user_id}"),
            delete_key_redis(f"hubspot_verifier:{org_id}:{user_id}"),
        )

    # Store credentials in Redis
    await add_key_value_redis(f"hubspot_credentials:{org_id}:{user_id}", json.dumps(response.json()), expire=600)

    # Return HTML to close the popup window
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    # Get credentials from Redis
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')

    # Parse credentials and delete from Redis
    credentials = json.loads(credentials)
    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")

    return credentials


def create_integration_item_metadata_object(
    response_json: str, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    parent_id = None if parent_id is None else parent_id + '_Base'
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None) + '_' + item_type,
        name=response_json.get('properties', None).get('name', None),
        domain=response_json.get('properties', None).get('domain', None),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )
    return integration_item_metadata



def fetch_items(access_token: str, url: str, aggregated_response: list, after=None):
    params = {'limit': 100}
    if after:
        params['after'] = after
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        json_data = response.json()
        results = json_data.get('results', [])
        for item in results:
            aggregated_response.append(item)

        paging = json_data.get('paging', {})
        next_page = paging.get('next', {}).get('after')
        if next_page:
            fetch_items(access_token, url, aggregated_response, next_page)


async def get_items_hubspot(credentials):
    if isinstance(credentials, str):
        credentials = json.loads(credentials)
    url = 'https://api.hubapi.com/crm/v3/objects/companies'
    list_of_integration_item_metadata = []
    list_of_responses = []
    fetch_items(credentials.get('access_token'), url, list_of_responses)
    for response in list_of_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'hubspot_company')
        )
    return list_of_integration_item_metadata