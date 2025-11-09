import uuid
from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse
from typing import List, Dict

from py3xui import Api, Client, Inbound

from shop_bot.data_manager.database import get_host, get_key_by_email, get_setting
from shop_bot.modules.happ_encryption import encrypt_subscription_url_via_api_async, should_encrypt_for_happ

logger = logging.getLogger(__name__)

def login_to_host(host_url: str, username: str, password: str, inbound_id: int) -> tuple[Api | None, Inbound | None]:
    try:
        api = Api(host=host_url, username=username, password=password)
        api.login()
        inbounds: List[Inbound] = api.inbound.get_list()
        target_inbound = next((inbound for inbound in inbounds if inbound.id == inbound_id), None)
        
        if target_inbound is None:
            logger.error(f"Входящий трафик с ID '{inbound_id}' не найден на хосте '{host_url}'")
            return None, None
        return api, target_inbound
    except Exception as e:
        logger.error(f"Не удалось выполнить вход или получить входящий трафик для хоста '{host_url}': {e}", exc_info=True)
        return None, None

def get_connection_string(inbound: Inbound, user_uuid: str, host_url: str, remark: str) -> str | None:
    if not inbound: return None
    settings = inbound.stream_settings.reality_settings.get("settings")
    if not settings: return None
    
    public_key = settings.get("publicKey")
    fp = settings.get("fingerprint")
    server_names = inbound.stream_settings.reality_settings.get("serverNames")
    short_ids = inbound.stream_settings.reality_settings.get("shortIds")
    port = inbound.port
    
    if not all([public_key, server_names, short_ids]): return None
    
    parsed_url = urlparse(host_url)
    short_id = short_ids[0]
    
    connection_string = (
        f"vless://{user_uuid}@{parsed_url.hostname}:{port}"
        f"?type=tcp&security=reality&pbk={public_key}&fp={fp}&sni={server_names[0]}"
        f"&sid={short_id}&spx=%2F&flow=xtls-rprx-vision#{remark}"
    )
    return connection_string

async def get_plain_subscription_link(user_uuid: str, host_url: str, host_name: str | None = None, sub_token: str | None = None) -> str:
    """Build plain subscription URL without encryption.
    Priority:
    1) Host-specific subscription_url (xui_hosts.subscription_url)
    2) Fallback: domain/host_url + default path
    Supports optional token replacement if base contains "{token}".

    Returns plain subscription link (never encrypted).
    """
    host_base = None
    try:
        if host_name:
            host = get_host(host_name)
            if host:
                host_base = (host.get("subscription_url") or "").strip()
    except Exception:
        host_base = None

    base = (host_base or "").strip()

    plain_url = None

    if sub_token:
        if base:
            plain_url = base.replace("{token}", sub_token) if "{token}" in base else f"{base.rstrip('/')}/{sub_token}"
        else:
            domain = (get_setting("domain") or "").strip()
            parsed = urlparse(host_url)
            hostname = domain if domain else (parsed.hostname or "")
            scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
            plain_url = f"{scheme}://{hostname}/sub/{sub_token}"
    elif base:
        plain_url = base
    else:
        domain = (get_setting("domain") or "").strip()
        parsed = urlparse(host_url)
        hostname = domain if domain else (parsed.hostname or "")
        scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
        plain_url = f"{scheme}://{hostname}/sub/{user_uuid}?format=v2ray"

    return plain_url


async def get_subscription_link(user_uuid: str, host_url: str, host_name: str | None = None, sub_token: str | None = None) -> str:
    """Build subscription URL with the following priority:
    1) Host-specific subscription_url (xui_hosts.subscription_url)
    2) Fallback: domain/host_url + default path
    Supports optional token replacement if base contains "{token}".

    If happ encryption is enabled, returns encrypted link in format happ://crypt3/...
    ВАЖНО: Шифрование применяется ТОЛЬКО для приложения Happ
    """
    # Получаем обычную ссылку
    plain_url = await get_plain_subscription_link(user_uuid, host_url, host_name, sub_token)

    # Проверяем, нужно ли шифровать ссылку для Happ
    if should_encrypt_for_happ(host_name):
        try:
            encrypted_url = await encrypt_subscription_url_via_api_async(plain_url)
            if encrypted_url:
                logger.info(f"Ссылка подписки зашифрована для Happ (хост: '{host_name or 'unknown'}')")
                return encrypted_url
            else:
                logger.warning(f"Не удалось зашифровать ссылку для Happ, возвращаем обычную (хост: '{host_name or 'unknown'}')")
        except Exception as e:
            logger.error(f"Ошибка при шифровании ссылки подписки для Happ: {e}", exc_info=True)

    # Возвращаем обычную ссылку если шифрование отключено или не удалось
    return plain_url


async def get_app_subscription_link(user_uuid: str, host_url: str, host_name: str | None = None, sub_token: str | None = None, app_type: str = "plain") -> str:
    """Get subscription link for specific app type.

    Args:
        user_uuid: User UUID
        host_url: Host URL
        host_name: Host name (optional)
        sub_token: Subscription token (optional)
        app_type: Type of app - "happ", "v2raytun", "streisand", or "plain"

    Returns:
        Subscription link formatted for the specified app:
        - "happ": Encrypted link (happ://crypt3/...) if encryption enabled, otherwise plain
        - "v2raytun": Always plain subscription link
        - "streisand": Always plain subscription link
        - "plain": Always plain subscription link
    """
    # Получаем обычную ссылку
    plain_url = await get_plain_subscription_link(user_uuid, host_url, host_name, sub_token)

    # Только для Happ применяем шифрование (если включено)
    if app_type == "happ" and should_encrypt_for_happ(host_name):
        try:
            encrypted_url = await encrypt_subscription_url_via_api_async(plain_url)
            if encrypted_url:
                logger.info(f"Ссылка подписки зашифрована для Happ (хост: '{host_name or 'unknown'}')")
                return encrypted_url
            else:
                logger.warning(f"Не удалось зашифровать ссылку для Happ, возвращаем обычную (хост: '{host_name or 'unknown'}')")
        except Exception as e:
            logger.error(f"Ошибка при шифровании ссылки подписки для Happ: {e}", exc_info=True)

    # Для всех остальных приложений (v2raytun, streisand) или если шифрование отключено/не удалось
    return plain_url


async def shorten_url_via_shortio(original_url: str) -> str | None:
    """Shorten URL using short.io API.

    Args:
        original_url: The URL to shorten (can be custom protocol like happ://)

    Returns:
        Shortened HTTPS URL or None if failed
    """
    import aiohttp

    api_key = get_setting("shortio_api_key")
    domain = get_setting("shortio_domain")

    if not api_key or not domain:
        logger.warning("short.io API key or domain not configured")
        return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.short.io/links",
                json={
                    "originalURL": original_url,
                    "domain": domain,
                    "allowDuplicates": False,
                    "skipQS": False,
                    "archived": False,
                    "cloaking": False
                },
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                    "Authorization": api_key
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    short_url = data.get("shortURL") or data.get("secureShortURL")
                    if short_url:
                        logger.info(f"URL successfully shortened via short.io: {short_url}")
                        return short_url
                    else:
                        logger.error(f"short.io API didn't return shortURL. Response: {data}")
                        return None
                else:
                    text = await resp.text()
                    logger.error(f"short.io API returned status {resp.status}: {text}")
                    return None
    except Exception as e:
        logger.error(f"Error shortening URL via short.io: {e}", exc_info=True)
        return None


async def get_subscription_link_for_key(key_data: dict, app_type: str = "plain", use_redirect: bool = False) -> str | None:
    """Get subscription link for a specific key and app type.

    This function retrieves the subscription token from the XUI panel and generates
    the appropriate subscription link for the specified app type.

    Args:
        key_data: Dictionary containing key information (must have 'xui_client_uuid', 'host_name', 'key_email')
        app_type: Type of app - "happ", "v2raytun", "streisand", or "plain"
        use_redirect: If True, wraps the link in an HTTPS redirect URL for Telegram URL buttons

    Returns:
        Subscription link formatted for the specified app, or None if error occurs
        If use_redirect=True, returns HTTPS URL that redirects to custom protocol
    """
    from shop_bot.data_manager.database import get_host

    host_name = key_data.get('host_name')
    if not host_name:
        logger.error(f"Не удалось получить ссылку подписки: отсутствует host_name для key_id {key_data.get('key_id')}")
        return None

    host_db_data = get_host(host_name)
    if not host_db_data:
        logger.error(f"Не удалось получить ссылку подписки: хост '{host_name}' не найден в базе данных.")
        return None

    # Login to host and get inbound
    api, inbound = login_to_host(
        host_url=host_db_data['host_url'],
        username=host_db_data['host_username'],
        password=host_db_data['host_pass'],
        inbound_id=host_db_data['host_inbound_id']
    )
    if not api or not inbound:
        logger.error(f"Не удалось подключиться к хосту '{host_name}' для получения ссылки подписки")
        return None

    # Extract subscription token from client
    client_sub_token = None
    try:
        if inbound.settings and inbound.settings.clients:
            for client in inbound.settings.clients:
                if getattr(client, "id", None) == key_data['xui_client_uuid'] or getattr(client, "email", None) == key_data.get('key_email'):
                    candidate_fields = ("subId", "subscription", "sub_id", "subscriptionId", "subscription_token")
                    for attr in candidate_fields:
                        val = None
                        if hasattr(client, attr):
                            val = getattr(client, attr)
                        else:
                            try:
                                val = client.get(attr)
                            except Exception:
                                pass
                        if val:
                            client_sub_token = val
                            break
                    break
    except Exception as e:
        logger.warning(f"Не удалось извлечь токен подписки из клиента: {e}")

    # Generate subscription link
    subscription_link = await get_app_subscription_link(
        key_data['xui_client_uuid'],
        host_db_data['host_url'],
        host_name,
        sub_token=client_sub_token,
        app_type=app_type
    )

    # If use_redirect is True and app_type is not plain, create shortened URL
    if use_redirect and app_type in ("happ", "v2raytun", "streisand"):
        # Build custom protocol URL
        if app_type == "happ":
            # For Happ, use the subscription_link as-is (already encrypted if enabled)
            if subscription_link.startswith("happ://"):
                # Already in custom protocol format
                custom_url = subscription_link
            else:
                # Plain HTTPS URL, wrap in happ://add/
                from urllib.parse import quote
                custom_url = f"happ://add/{quote(subscription_link, safe='')}"
        elif app_type == "v2raytun":
            from urllib.parse import quote
            custom_url = f"v2raytun://import/{quote(subscription_link, safe='')}"
        elif app_type == "streisand":
            from urllib.parse import quote
            custom_url = f"streisand://import/{quote(subscription_link, safe='')}"
        else:
            custom_url = subscription_link

        # Shorten the custom protocol URL
        shortened = await shorten_url_via_shortio(custom_url)
        if shortened:
            return shortened
        else:
            # Fallback to original link if shortening fails
            logger.warning(f"Failed to shorten URL for {app_type}, returning original")
            return subscription_link

    return subscription_link


def update_or_create_client_on_panel(api: Api, inbound_id: int, email: str, days_to_add: int | None = None, target_expiry_ms: int | None = None) -> tuple[str | None, int | None, str | None]:
    try:
        inbound_to_modify = api.inbound.get_by_id(inbound_id)
        if not inbound_to_modify:
            raise ValueError(f"Could not find inbound with ID {inbound_id}")

        if inbound_to_modify.settings.clients is None:
            inbound_to_modify.settings.clients = []
            
        client_index = -1
        for i, client in enumerate(inbound_to_modify.settings.clients):
            if client.email == email:
                client_index = i
                break
        
        # Determine new expiry time
        if target_expiry_ms is not None:
            new_expiry_ms = int(target_expiry_ms)
        else:
            if days_to_add is None:
                raise ValueError("Either days_to_add or target_expiry_ms must be provided")
            if client_index != -1:
                existing_client = inbound_to_modify.settings.clients[client_index]
                if existing_client.expiry_time > int(datetime.now().timestamp() * 1000):
                    current_expiry_dt = datetime.fromtimestamp(existing_client.expiry_time / 1000)
                    new_expiry_dt = current_expiry_dt + timedelta(days=days_to_add)
                else:
                    new_expiry_dt = datetime.now() + timedelta(days=days_to_add)
            else:
                new_expiry_dt = datetime.now() + timedelta(days=days_to_add)

            new_expiry_ms = int(new_expiry_dt.timestamp() * 1000)

        client_sub_token: str | None = None

        if client_index != -1:
            # Disable auto-reset/auto-renew on extension
            try:
                inbound_to_modify.settings.clients[client_index].reset = 0
            except Exception:
                pass
            inbound_to_modify.settings.clients[client_index].enable = True
            inbound_to_modify.settings.clients[client_index].expiry_time = new_expiry_ms

            existing_client = inbound_to_modify.settings.clients[client_index]
            client_uuid = existing_client.id
            try:
                sub_token_existing = None
                for attr in ("subId", "subscription", "sub_id"):
                    if hasattr(existing_client, attr):
                        val = getattr(existing_client, attr)
                        if val:
                            sub_token_existing = val
                            break
                if sub_token_existing:
                    client_sub_token = sub_token_existing
                else:
                    import secrets
                    client_sub_token = secrets.token_hex(12)
                    for attr in ("subId", "subscription", "sub_id"):
                        try:
                            setattr(existing_client, attr, client_sub_token)
                        except Exception:
                            pass
            except Exception:
                pass
        else:
            client_uuid = str(uuid.uuid4())
            new_client = Client(
                id=client_uuid,
                email=email,
                enable=True,
                flow="xtls-rprx-vision",
                expiry_time=new_expiry_ms
            )
            # Ensure no auto-reset/auto-renew for new clients
            try:
                setattr(new_client, "reset", 0)
            except Exception:
                pass

            try:
                import secrets
                client_sub_token = secrets.token_hex(12)
                for attr in ("subId", "subscription", "sub_id"):
                    try:
                        setattr(new_client, attr, client_sub_token)
                    except Exception:
                        pass
            except Exception:
                pass
            inbound_to_modify.settings.clients.append(new_client)

        api.inbound.update(inbound_id, inbound_to_modify)

        return client_uuid, new_expiry_ms, client_sub_token

    except Exception as e:
        logger.error(f"Ошибка в update_or_create_client_on_panel: {e}", exc_info=True)
        return None, None, None

async def create_or_update_key_on_host(host_name: str, email: str, days_to_add: int | None = None, expiry_timestamp_ms: int | None = None) -> Dict | None:
    host_data = get_host(host_name)
    if not host_data:
        logger.error(f"Сбой рабочего процесса: Хост '{host_name}' не найден в базе данных.")
        return None

    api, inbound = login_to_host(
        host_url=host_data['host_url'],
        username=host_data['host_username'],
        password=host_data['host_pass'],
        inbound_id=host_data['host_inbound_id']
    )
    if not api or not inbound:
        logger.error(f"Сбой рабочего процесса: Не удалось войти или найти inbound на хосте '{host_name}'.")
        return None
        
    # Prefer exact expiry when provided (e.g., switching hosts), otherwise add days (purchase/extend/trial)
    client_uuid, new_expiry_ms, client_sub_token = update_or_create_client_on_panel(
        api, inbound.id, email, days_to_add=days_to_add, target_expiry_ms=expiry_timestamp_ms
    )

    if not client_uuid:
        logger.error(f"Сбой рабочего процесса: Не удалось создать/обновить клиента '{email}' на хосте '{host_name}'.")
        return None

    connection_string = await get_subscription_link(client_uuid, host_data['host_url'], host_name, sub_token=client_sub_token)

    logger.info(f"Успешно обработан ключ для '{email}' на хосте '{host_name}'.")


    return {
        "client_uuid": client_uuid,
        "email": email,
        "expiry_timestamp_ms": new_expiry_ms,
        "connection_string": connection_string,
        "host_name": host_name
    }

async def get_key_details_from_host(key_data: dict) -> dict | None:
    host_name = key_data.get('host_name')
    if not host_name:
        logger.error(f"Не удалось получить данные ключа: отсутствует host_name для key_id {key_data.get('key_id')}")
        return None

    host_db_data = get_host(host_name)
    if not host_db_data:
        logger.error(f"Не удалось получить данные ключа: хост '{host_name}' не найден в базе данных.")
        return None

    api, inbound = login_to_host(
        host_url=host_db_data['host_url'],
        username=host_db_data['host_username'],
        password=host_db_data['host_pass'],
        inbound_id=host_db_data['host_inbound_id']
    )
    if not api or not inbound: return None

    client_sub_token = None
    try:
        if inbound.settings and inbound.settings.clients:
            for client in inbound.settings.clients:
                if getattr(client, "id", None) == key_data['xui_client_uuid'] or getattr(client, "email", None) == key_data.get('email'):
                    candidate_fields = ("subId", "subscription", "sub_id", "subscriptionId", "subscription_token")
                    for attr in candidate_fields:
                        val = None
                        if hasattr(client, attr):
                            val = getattr(client, attr)
                        else:
                            try:
                                val = client.get(attr)
                            except Exception:
                                pass
                        if val:
                            client_sub_token = val
                            break
                    break
    except Exception:
        pass
    connection_string = await get_subscription_link(key_data['xui_client_uuid'], host_db_data['host_url'], host_name, sub_token=client_sub_token)
    return {"connection_string": connection_string}

async def delete_client_on_host(host_name: str, client_email: str) -> bool:
    host_data = get_host(host_name)
    if not host_data:
        logger.error(f"Не удалось удалить клиента: хост '{host_name}' не найден.")
        return False

    api, inbound = login_to_host(
        host_url=host_data['host_url'],
        username=host_data['host_username'],
        password=host_data['host_pass'],
        inbound_id=host_data['host_inbound_id']
    )

    if not api or not inbound:
        logger.error(f"Не удалось удалить клиента: ошибка входа или поиска inbound для хоста '{host_name}'.")
        return False
        
    try:
        client_to_delete = get_key_by_email(client_email)
        if client_to_delete:
            api.client.delete(inbound.id, client_to_delete['xui_client_uuid'])
            logger.info(f"Клиент '{client_email}' успешно удалён с хоста '{host_name}'.")
            return True
        else:
            logger.warning(f"Клиент с email '{client_email}' не найден на хосте '{host_name}' для удаления (возможно, уже удалён).")
            return True
            
    except Exception as e:
        logger.error(f"Не удалось удалить клиента '{client_email}' с хоста '{host_name}': {e}", exc_info=True)
        return False