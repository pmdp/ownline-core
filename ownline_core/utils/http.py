import aiohttp
import logging

logger = logging.getLogger("ownline_core_log")


async def do_request_to_ownline_web_api(data, auth_token, endpoint):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": auth_token,
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(endpoint, json=data, headers=headers) as response:
            logger.info(
                f"Request to ownline-web endpoint: {endpoint} done: status:({response.status}), reason:({response.reason})")
