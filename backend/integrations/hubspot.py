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


# ------------------------------------------
# STEP 1: Generate Authorization URL
# ------------------------------------------
"""
    authorize_hubspot(user_id: str, org_id: str) -> str

    Generates a secure OAuth URL to redirect the user to HubSpot for login and authorization.

    - Stores a unique state in Redis for CSRF protection.
    - Builds the authorization URL with client_id, redirect_uri, scope, and encoded state.

    @param user_id: ID of the user initiating the request
    @param org_id: Organization ID
    @return: A complete HubSpot authorization URL to open in the frontend
"""
async def authorize_hubspot(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id
    }

    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    await add_key_value_redis(f"hubspot_state:{org_id}:{user_id}", json.dumps(state_data), expire=600)

    code_verifier = secrets.token_urlsafe(32)
    await add_key_value_redis(f"hubspot_verifier:{org_id}:{user_id}", code_verifier, expire=600)

    query_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": encoded_state
    }

    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(query_params)}"
    return auth_url


# ------------------------------------------
# STEP 2: Handle OAuth Callback
# ------------------------------------------
"""
    oauth2callback_hubspot(request: Request) -> HTMLResponse

    Handles the OAuth redirect from HubSpot after user login.
    - Verifies the state to ensure it's secure.
    - Exchanges the temporary code for an access token.
    - Stores the credentials in Redis for retrieval by the frontend.

    @param request: FastAPI Request object containing query params from HubSpot
    @return: HTML response that closes the popup window in the frontend
"""
async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))

    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f"hubspot_state:{org_id}:{user_id}"),
        get_value_redis(f"hubspot_verifier:{org_id}:{user_id}"),
    )

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

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
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ),
            delete_key_redis(f"hubspot_state:{org_id}:{user_id}"),
            delete_key_redis(f"hubspot_verifier:{org_id}:{user_id}"),
        )

    await add_key_value_redis(f"hubspot_credentials:{org_id}:{user_id}", json.dumps(response.json()), expire=600)

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


# ------------------------------------------
# STEP 3: Get Stored Credentials
# ------------------------------------------
"""
    get_hubspot_credentials(user_id: str, org_id: str) -> dict

    Retrieves the stored access token from Redis after successful OAuth.

    @param user_id: ID of the user
    @param org_id: Organization ID
    @return: A dictionary containing the access token and other auth info
"""
async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')

    credentials = json.loads(credentials)
    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")
    return credentials


# ------------------------------------------
# STEP 4: Normalize HubSpot Record
# ------------------------------------------
"""
    create_integration_item_metadata_object(response_json: dict, item_type: str, ...) -> IntegrationItem

    Converts a raw HubSpot record into a standardized IntegrationItem object.

    @param response_json: Raw company object from HubSpot API
    @param item_type: Type of item (e.g., 'hubspot_company')
    @param parent_id: Optional parent ID
    @param parent_name: Optional parent name
    @return: IntegrationItem instance with normalized structure
"""
def create_integration_item_metadata_object(
        response_json: dict, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    parent_id = None if parent_id is None else parent_id + '_Base'
    properties = response_json.get('properties', {})

    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', '') + '_' + item_type,
        name=properties.get('name', 'Unnamed'),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )
    return integration_item_metadata


# ------------------------------------------
# STEP 5: Fetch Paginated HubSpot Data
# ------------------------------------------
"""
    fetch_items(access_token: str, url: str, aggregated_response: list, after: str = None)

    Fetches all pages of company data from the HubSpot API using pagination.
    Appends results to a shared list.

    @param access_token: OAuth token for HubSpot
    @param url: HubSpot API endpoint
    @param aggregated_response: List to store all records
    @param after: Optional pagination token from previous response
    @return: None (modifies aggregated_response in-place)
"""
def fetch_items(access_token: str, url: str, aggregated_response: list, after=None):
    params = {'limit': 100}
    if after:
        params['after'] = after
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        json_data = response.json()
        results = json_data.get('results', [])
        aggregated_response.extend(results)

        paging = json_data.get('paging', {})
        next_page = paging.get('next', {}).get('after')
        if next_page:
            fetch_items(access_token, url, aggregated_response, next_page)


# ------------------------------------------
# STEP 6: Main Load Function
# ------------------------------------------
"""
    get_items_hubspot(credentials: dict or str) -> list[IntegrationItem]

    Loads company records from HubSpot using the given credentials,
    normalizes them, and returns them as IntegrationItem objects.

    @param credentials: Auth token either as dict or JSON string
    @return: List of IntegrationItem objects for the frontend
"""
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
