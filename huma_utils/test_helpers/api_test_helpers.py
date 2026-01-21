from typing import Any, Callable

import httpx
from orjson import orjson  # type: ignore[attr-defined]

TEST_APP_HOSTNAME = "test"
TEST_APP_BASE_URL = f"http://{TEST_APP_HOSTNAME}"


async def post_request(
    app: Callable[..., Any],
    endpoint: str,
    data: dict[str, Any] | str,
    additional_headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> httpx.Response:
    content: str | bytes = data if isinstance(data, str) else orjson.dumps(data)
    headers = {
        "Content-Type": "application/json",
    }
    if additional_headers is not None:
        headers = {**headers, **additional_headers}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=TEST_APP_BASE_URL
    ) as client:
        return await client.post(
            url=endpoint,
            headers=headers,
            content=content,
            cookies=cookies,
        )
