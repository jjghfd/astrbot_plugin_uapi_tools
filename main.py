import asyncio
import re
import ipaddress
from typing import Any, Tuple, Optional

from uapi import UapiClient
from uapi.errors import UapiError

from astrbot.api.event import filter, AstrMessageEvent
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
        timeout = config.get("timeout", 10)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            logger.warning(f"Invalid timeout value: {timeout}, using default 10")
            timeout = 10
        self.timeout = timeout
        # 添加并发控制信号量，限制最大并发请求数
        self.semaphore = asyncio.Semaphore(10)

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
                key_l = key.lower()
                # Skip ping delay/latency related fields, empty/null values, and punycode
                if (
                    key_l in ["min", "avg", "max", "mdev", "time", "id", "punycode"]
                    or value is None
                    or value == ""
                ):
                    continue

                translated_key = self.key_translations.get(key_l, key)
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

    def _validate_domain(self, domain: str) -> Tuple[bool, str]:
        """验证域名合法性"""
        if not domain:
            return False, "❌ 请输入有效的域名或 IP 地址。"

        # 验证 IP 地址
        try:
            # 尝试解析为 IPv4 或 IPv6
            ipaddress.ip_address(domain)
            return True, ""
        except ValueError:
            # 不是有效的 IP 地址，尝试验证为域名
            pass

        # 验证域名
        # 域名基本格式校验，修复边界条件，允许单字符主机名
        domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$"
        if not re.match(domain_pattern, domain):
            return False, "❌ 请输入有效的域名或 IP 地址。"

        # 检查域名长度和标签
        labels = domain.split(".")
        for label in labels:
            if len(label) > 63:
                return False, "❌ 域名标签长度不能超过 63 个字符。"

        if len(domain) > 253:
            return False, "❌ 域名总长度不能超过 253 个字符。"

        return True, ""

    async def _execute_async_request(
        self, func, *args, **kwargs
    ) -> Tuple[Optional[Any], str]:
        """通用的异步请求执行器"""
        # 获取函数名和参数信息，用于更详细的日志记录
        func_name = getattr(func, "__name__", str(func))
        params_info = {}
        if kwargs:
            params_info.update(kwargs)
        if args:
            # 尝试从位置参数中提取有意义的信息
            for i, arg in enumerate(args):
                if isinstance(arg, str) and (
                    "domain" in func_name.lower() or "host" in func_name.lower()
                ):
                    params_info["target"] = arg
                    break

        # 使用信号量控制并发
        async with self.semaphore:
            try:
                # 确保使用正确的参数传递方式
                result = await asyncio.wait_for(
                    asyncio.to_thread(
                        lambda: func(*args, **kwargs)
                    ),  # 使用 lambda 确保正确传递
                    timeout=self.timeout,
                )
                return result, ""
            except asyncio.TimeoutError:
                logger.warning(f"Request timed out: {func_name}, params: {params_info}")
                return None, "❌ 请求超时，请稍后重试。"
            except UapiError as exc:
                logger.error(
                    f"UAPI error: {func_name}, params: {params_info}, error: {exc}"
                )
                return None, "❌ 请求失败，请检查输入参数或稍后重试。"
            except Exception as e:
                logger.error(
                    f"Unexpected error: {func_name}, params: {params_info}, error: {e}",
                    exc_info=True,
                )
                return None, "❌ 发生内部错误，请联系管理员。"

    async def _execute_async_request_with_retry(
        self, func, max_retries=3, *args, **kwargs
    ) -> Tuple[Optional[Any], str]:
        """带重试机制的异步请求执行器"""
        # 只对超时错误等网络瞬时故障进行重试
        retryable_errors = []

        for attempt in range(max_retries):
            result, error = await self._execute_async_request(func, *args, **kwargs)
            if not error:
                return result, error

            # 检查是否是可重试的错误（这里通过错误消息判断，实际项目中可以通过异常类型判断）
            if "超时" in error:
                if attempt < max_retries - 1:
                    logger.info(
                        f"Request timed out, retrying {attempt + 1}/{max_retries - 1}..."
                    )
                    await asyncio.sleep(1 * (attempt + 1))  # 退避策略
                    retryable_errors.append(error)
                else:
                    # 最后一次重试失败
                    return None, error
            else:
                # 非可重试错误，直接返回
                return None, error

        # 所有重试都失败
        return None, "请求失败，已达最大重试次数"

    def _process_result(self, result, title):
        """Helper to process API result and extract data if possible."""
        # 处理空结果
        if not result:
            return f"{title}\n暂无数据"

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
                    # 更友好的错误信息
                    error_msg = result.get("msg", "未知错误")
                    error_code = result.get("code", "N/A")
                    return f"❌ {title}\n错误代码: {error_code}\n错误信息: {error_msg}"

            # If structure is unknown, print the whole dict
            return f"{title}\n" + self._format_data(result)

        elif isinstance(result, list):
            return f"{title}\n" + self._format_data(result)

        return f"{title}\n{result}"

    async def _get_whois(self, domain: str) -> str:
        # 验证域名合法性
        valid, error_msg = self._validate_domain(domain)
        if not valid:
            return error_msg

        # 执行异步请求（带重试机制）
        result, error_msg = await self._execute_async_request_with_retry(
            self.client.network.get_network_whois, domain=domain, format="json"
        )
        if error_msg:
            logger.warning(
                f"WHOIS request failed for domain: {domain}, error: {error_msg}"
            )
            return error_msg

        return self._process_result(result, f"🔍 WHOIS 查询结果 ({domain}):")

    # ---------------- DNS ----------------
    @filter.command("dns")
    async def dns_cmd(
        self, event: AstrMessageEvent, domain: str = "", record_type: str = "A"
    ):
        """查询域名 DNS 解析记录"""
        if not domain:
            yield event.plain_result("请输入域名，例如：/dns cn.bing.com A")
            return
        result = await self._get_dns(domain, record_type)

        # 调用发送转发消息的方法
        async for msg in self.send_forward_message(event, result, "DNS查询结果"):
            yield msg

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
        # 验证域名合法性
        valid, error_msg = self._validate_domain(domain)
        if not valid:
            return error_msg

        # Validate record_type
        valid_record_types = [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "TXT",
            "NS",
            "SOA",
            "PTR",
            "SRV",
            "CAA",
            "NAPTR",
        ]
        if record_type.upper() not in valid_record_types:
            return f"❌ 不支持的记录类型。支持的记录类型：{', '.join(valid_record_types)}。"

        # 执行异步请求（带重试机制），统一使用大写记录类型
        result, error_msg = await self._execute_async_request_with_retry(
            self.client.network.get_network_dns, domain=domain, type=record_type.upper()
        )
        if error_msg:
            logger.warning(
                f"DNS request failed for domain: {domain}, type: {record_type}, error: {error_msg}"
            )
            return error_msg

        return self._process_result(
            result, f"🔍 DNS 查询结果 ({domain}, 类型: {record_type}):"
        )

    # ---------------- Ping ----------------
    @filter.command("ping")
    async def ping_cmd(self, event: AstrMessageEvent, host: str = ""):
        """Ping 主机"""
        if not host:
            yield event.plain_result("请输入主机名或 IP，例如：/ping cn.bing.com")
            return
        result = await self._ping_host(host)

        # 调用发送转发消息的方法
        async for msg in self.send_forward_message(event, result, "Ping检测结果"):
            yield msg

    @filter.llm_tool(name="ping_host")
    async def ping_host(self, event: AstrMessageEvent, host: str):
        """Ping 主机检测连通性。

        Args:
            host (str): 域名或 IP 地址
        """
        return await self._ping_host(host)

    async def _ping_host(self, host: str) -> str:
        # 验证主机合法性
        valid, error_msg = self._validate_domain(host)
        if not valid:
            return error_msg

        # 执行异步请求（带重试机制）
        result, error_msg = await self._execute_async_request_with_retry(
            self.client.network.get_network_ping, host=host
        )
        if error_msg:
            logger.warning(f"Ping request failed for host: {host}, error: {error_msg}")
            return error_msg

        return self._process_result(result, f"📶 Ping 检测结果 ({host}):")

    # ---------------- Help ----------------
    @filter.command("uapi")
    async def help_cmd(self, event: AstrMessageEvent, subcommand: str = "help"):
        """查看帮助信息"""
        if subcommand != "help":
            yield event.plain_result("请使用 /uapi help 查看帮助信息")
            return

        help_text = """
🔍 UAPI 工具命令：
/whois <domain> - 查询域名 WHOIS 信息，例如：/whois google.com
/dns <domain> [record_type] - 查询域名 DNS 解析记录，例如：/dns cn.bing.com A
  支持的记录类型：A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA, NAPTR
/ping <host> - Ping 主机检测连通性，例如：/ping cn.bing.com
/uapi help - 查看此帮助信息
        """
        yield event.plain_result(help_text)
