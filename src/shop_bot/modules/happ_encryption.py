"""
Модуль для шифрования ссылок подписки в формате happ://crypt3/
Использует внешний API crypto.happ.su для шифрования согласно спецификации из happ_link.md
ВАЖНО: Шифрование применяется ТОЛЬКО для приложения Happ
"""

import logging
import asyncio
from typing import Optional
import aiohttp

logger = logging.getLogger(__name__)


async def encrypt_subscription_url_via_api_async(url: str) -> Optional[str]:
    """
    Шифрует URL подписки через API crypto.happ.su для приложения Happ
    Возвращает зашифрованную ссылку в формате happ://crypt3/

    Args:
        url: URL подписки для шифрования

    Returns:
        Зашифрованная ссылка в формате happ://crypt3/... или None при ошибке
    """
    if not url:
        logger.warning("Попытка зашифровать пустой URL")
        return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'https://crypto.happ.su/api.php',
                json={'url': url},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # API возвращает encrypted_link, а не encrypted_url
                    encrypted = data.get('encrypted_link') or data.get('encrypted_url') or data.get('url') or data.get('link')
                    if encrypted:
                        logger.info(f"URL успешно зашифрован через API crypto.happ.su для Happ")
                        return encrypted
                    else:
                        logger.error(f"API crypto.happ.su не вернул зашифрованный URL. Ответ: {data}")
                        return None
                else:
                    text = await resp.text()
                    logger.error(f"API crypto.happ.su вернул статус {resp.status}: {text}")
                    return None

    except asyncio.TimeoutError:
        logger.error("Таймаут при обращении к API crypto.happ.su")
        return None
    except Exception as e:
        logger.error(f"Ошибка при шифровании через API crypto.happ.su: {e}", exc_info=True)
        return None


def should_encrypt_for_happ(host_name: Optional[str] = None) -> bool:
    """
    Проверяет, нужно ли шифровать ссылку подписки для приложения Happ
    ВАЖНО: Шифрование применяется ТОЛЬКО для Happ приложения

    Args:
        host_name: Имя хоста (опционально, для проверки настроек конкретного хоста)

    Returns:
        True если нужно шифровать для Happ, False иначе
    """
    from shop_bot.data_manager.database import get_setting, get_host

    try:
        # Проверяем глобальную настройку для Happ
        global_encrypt = get_setting("happ_encrypt_subscription")
        if global_encrypt is not None:
            # Конвертируем в boolean
            if isinstance(global_encrypt, str):
                return global_encrypt.lower() in ('true', '1', 'yes', 'on')
            return bool(global_encrypt)

        # Если есть имя хоста, проверяем настройку для конкретного хоста
        if host_name:
            host = get_host(host_name)
            if host:
                host_encrypt = host.get("happ_encrypt_subscription")
                if host_encrypt is not None:
                    if isinstance(host_encrypt, str):
                        return host_encrypt.lower() in ('true', '1', 'yes', 'on')
                    return bool(host_encrypt)

        # По умолчанию шифрование для Happ включено
        return True

    except Exception as e:
        logger.error(f"Ошибка при проверке настройки шифрования Happ: {e}", exc_info=True)
        # По умолчанию включаем шифрование для безопасности
        return True

