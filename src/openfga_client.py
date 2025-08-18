from __future__ import annotations

import requests


class OpenFGAClient:
    """Simple client for interacting with OpenFGA HTTP API for authorization models.

    This client only implements the minimal subset required by the charm:
    - Create an authorization model
    - Get an authorization model by ID
    """

    def __init__(self, base_url: str, store_id: str, token: str | None = None, verify: bool = False):
        self.base_url = base_url.rstrip("/")
        self.store_id = store_id
        self.token = token
        self.verify = verify

    @property
    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def create_authorization_model(self, model: dict) -> str:
        """Create a new authorization model.

        Args:
            model: A dict representing the authorization model payload.

        Returns:
            The created authorization model ID.

        Raises:
            ValueError: If the request fails or the response is missing the model ID.
        """
        url = f"{self.base_url}/stores/{self.store_id}/authorization-models"
        try:
            resp = requests.post(url, json=model, headers=self._headers, verify=self.verify)
        except requests.exceptions.RequestException as e:
            raise ValueError(f"failed to create authorisation model - {e}") from e
        if not resp.ok:
            raise ValueError(f"failed to create authorisation model - {resp.text}")
        data = resp.json()
        model_id = data.get("authorization_model_id")
        if not model_id:
            raise ValueError("response does not contain authorization model id")
        return model_id

    def get_authorization_model(self, model_id: str) -> dict | None:
        """Fetch an authorization model by ID.

        Args:
            model_id: The authorization model ID.

        Returns:
            The authorization model as a dict, or None if not found (404).

        Raises:
            ValueError: If the request fails with a non-404 error.
        """
        url = f"{self.base_url}/stores/{self.store_id}/authorization-models/{model_id}"
        try:
            resp = requests.get(url, headers=self._headers, verify=self.verify)
        except requests.exceptions.RequestException as e:
            raise ValueError(f"failed to fetch authorisation model - {e}") from e
        if resp.status_code == 404:
            return None
        if not resp.ok:
            raise ValueError(f"failed to fetch authorisation model - {resp.text}")
        return resp.json()
