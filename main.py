import asyncio

from uapi import UapiClient
from uapi.errors import UapiError

from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star
from astrbot.api.message_components import Node, Plain
from astrbot.api import logger
from astrbot.api import AstrBotConfig


class UapiToolsPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.client = UapiClient("https://uapis.cn")
        self.config = config
        # 从配置中获取字段映射，默认为空字典
        self.key_translations = config.get("key_translations", {})
        # 从配置中获取超时时间，默认为10秒
        self.timeout = config.get("timeout", 10)

    # ---------------- WHOIS ----------------
    async def send_forward_message(
        self, event: AstrMessageEvent, content: str, title: str = "Whois查询结果"
    ):
        """发送转发消息"""
        try:
            # 尝试使用 Node 方式发送合并消息
            logger.info(f"Attempting to send forward message with title: {title}")
            logger.info(f"Self ID: {event.message_obj.self_id}")

            # 创建 Node 对象
            node = Node(
                uin=event.message_obj.self_id, name=title, content=[Plain(content)]
            )

            logger.info(f"Created Node object: {node}")

            # 发送合并消息
            yield event.chain_result([node])
            logger.info("Forward message sent successfully")
        except Exception as e:
            logger.error(f"Failed to send forward message: {e}")
            # Fallback to plain text if forward message fails (e.g. not supported by adapter)
            yield event.plain_result(content)

    @filter.command("whois")
    async def whois_cmd(self, event: AstrMessageEvent, domain: str = ""):
        """查询域名 WHOIS 信息"""
        if not domain:
            yield event.plain_result("请输入域名，例如：/whois google.com")
            return
        result = await self._get_whois(domain)

        # 调用发送转发消息的方法
        async for msg in self.send_forward_message(event, result, "Whois查询结果"):
            yield msg

    @filter.llm_tool(name="get_whois")
    async def get_whois(self, event: AstrMessageEvent, domain: str):
        """查询域名 WHOIS 信息。

        Args:
            domain (str): 域名，例如 "google.com"
        """
        return await self._get_whois(domain)

    def _format_data(self, data, indent=0):
        """Recursively format data into a readable string."""
        spacing = "  " * indent
        if isinstance(data, dict):
            lines = []
            for key, value in data.items():
                # Skip ping delay/latency related fields, empty/null values, and punycode
                if (
                    key in ["min", "avg", "max", "mdev", "time", "id", "punycode"]
                    or value is None
                    or value == ""
                ):
                    continue

                translated_key = self.key_translations.get(key.lower(), key)
                if isinstance(value, (dict, list)):
                    lines.append(f"{spacing}{translated_key}:")
                    lines.append(self._format_data(value, indent + 1))
                else:
                    lines.append(f"{spacing}{translated_key}: {value}")
            return "\n".join(lines)
        elif isinstance(data, list):
            lines = []
            for index, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    lines.append(f"{spacing}- 项目 {index + 1}:")
                    lines.append(self._format_data(item, indent + 1))
                else:
                    lines.append(f"{spacing}- {item}")
            return "\n".join(lines)
        else:
            return f"{spacing}{data}"

    def _process_result(self, result, title):
        """Helper to process API result and extract data if possible."""
        if isinstance(result, dict):
            # Check for standard API response structure: code, msg, data
            if "code" in result:
                code = result.get("code")
                # Accept both integer and string 200
                if str(code) == "200":
                    if "data" in result:
                        return f"{title}\n" + self._format_data(result["data"])
                    else:
                        return f"{title}\n暂无数据"
                else:
                    msg = result.get("msg", "未知错误")
                    return f"❌ 请求失败: {msg} (Code: {code})"

            # If structure is unknown, print the whole dict
            return f"{title}\n" + self._format_data(result)

        elif isinstance(result, list):
            return f"{title}\n" + self._format_data(result)

        return f"{title}\n{result}"

    async def _get_whois(self, domain: str) -> str:
        try:
            # Run in thread to avoid blocking
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    self.client.network.get_network_whois, domain=domain, format="json"
                ),
                timeout=self.timeout,
            )
            return self._process_result(result, f"🔍 WHOIS 查询结果 ({domain}):")
        except asyncio.TimeoutError:
            logger.warning(f"WHOIS request timed out for domain: {domain}")
            return "❌ 请求超时，请稍后重试。"
        except UapiError as exc:
            logger.error(f"UAPI WHOIS error for domain {domain}: {exc}")
            return "❌ 请求失败，请检查域名或稍后重试。"
        except Exception as e:
            logger.error(
                f"Unexpected error in WHOIS request for domain {domain}: {e}",
                exc_info=True,
            )
            return "❌ 发生内部错误，请联系管理员。"

    # ---------------- DNS ----------------
    @filter.command("DNS")
    async def dns_cmd(self, event: AstrMessageEvent, domain: str = ""):
        """查询域名 DNS 解析记录"""
        if not domain:
            yield event.plain_result("请输入域名，例如：/DNS cn.bing.com")
            return
        result = await self._get_dns(domain)
        yield event.plain_result(result)

    @filter.llm_tool(name="get_dns")
    async def get_dns(
        self, event: AstrMessageEvent, domain: str, record_type: str = "A"
    ):
        """查询域名 DNS 解析记录。

        Args:
            domain (str): 域名，例如 "cn.bing.com"
            record_type (str): 记录类型，例如 "A", "CNAME", "MX", "TXT", "NS", "AAAA"。默认为 "A"。
        """
        return await self._get_dns(domain, record_type)

    async def _get_dns(self, domain: str, record_type: str = "A") -> str:
        # Validate domain format
        if not domain or "." not in domain:
            return "❌ 请输入有效的域名（例如：example.com）。"

        # Validate record_type
        valid_record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
        if record_type.upper() not in valid_record_types:
            return f"❌ 不支持的记录类型。支持的记录类型：{', '.join(valid_record_types)}。"

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    self.client.network.get_network_dns, domain=domain, type=record_type
                ),
                timeout=self.timeout,
            )
            return self._process_result(
                result, f"🔍 DNS 查询结果 ({domain}, 类型: {record_type}):"
            )
        except asyncio.TimeoutError:
            logger.warning(
                f"DNS request timed out for domain: {domain}, type: {record_type}"
            )
            return "❌ 请求超时，请稍后重试。"
        except UapiError as exc:
            logger.error(
                f"UAPI DNS error for domain {domain}, type {record_type}: {exc}"
            )
            return "❌ 请求失败，请检查域名或记录类型。"
        except Exception as e:
            logger.error(
                f"Unexpected error in DNS request for domain {domain}, type {record_type}: {e}",
                exc_info=True,
            )
            return "❌ 发生内部错误，请联系管理员。"

    # ---------------- Ping ----------------
    @filter.command("ping")
    async def ping_cmd(self, event: AstrMessageEvent, host: str = ""):
        """Ping 主机"""
        if not host:
            yield event.plain_result("请输入主机名或 IP，例如：/ping cn.bing.com")
            return
        result = await self._ping_host(host)
        yield event.plain_result(result)

    @filter.llm_tool(name="ping_host")
    async def ping_host(self, event: AstrMessageEvent, host: str):
        """Ping 主机检测连通性。

        Args:
            host (str): 域名或 IP 地址
        """
        return await self._ping_host(host)

    async def _ping_host(self, host: str) -> str:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self.client.network.get_network_ping, host=host),
                timeout=self.timeout,
            )
            return self._process_result(result, f"📶 Ping 检测结果 ({host}):")
        except asyncio.TimeoutError:
            return f"❌ 请求超时，请稍后重试。"
        except UapiError as exc:
            return f"API error: {exc}"
        except Exception as e:
            return f"Error: {e}"
