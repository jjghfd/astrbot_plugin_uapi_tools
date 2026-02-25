import asyncio
import json

from uapi import UapiClient
from uapi.errors import UapiError

from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star
from astrbot.api.message_components import Node, Plain

class UapiToolsPlugin(Star):
    KEY_TRANSLATIONS = {
        # Common
        "code": "状态码",
        "msg": "消息",
        "data": "数据",
        # WHOIS
        "domain": "🌐 域名",
        "extension": "📂 后缀",
        "registrar": "🏢 注册商",
        "creation_date": "📅 创建日期",
        "created_date": "📅 创建日期",
        "created_date_in_time": "🕒 创建时间(UTC)",
        "expiration_date": "📅 过期日期",
        "expiration_date_in_time": "🕒 过期时间(UTC)",
        "updated_date": "📅 更新日期",
        "updated_date_in_time": "🕒 更新时间(UTC)",
        "status": "📊 状态",
        "name_servers": "🖥️ DNS服务器",
        "emails": "📧 联系邮箱",
        "dnssec": "🔒 DNSSEC",
        "name": "👤 名称",
        "org": "🏢 组织",
        "address": "📍 地址",
        "street": "🛣️ 街道",
        "city": "🏙️ 城市",
        "state": "🗺️ 省/州",
        "province": "🗺️ 省/州",
        "zipcode": "📮 邮编",
        "postal_code": "📮 邮编",
        "country": "🇨🇳 国家",
        "whois_server": "🖥️ Whois服务器",
        "phone": "📞 电话",
        "email": "📧 邮箱",
        "referral_url": "🔗 相关链接",
        "registrant": "👤 注册人信息",
        "admin": "👮 管理员信息",
        "technical": "🔧 技术联系人",
        "billing": "💰 账单联系人",
        "organization": "🏢 组织",
        
        # DNS
        "host": "🖥️ 主机",
        "type": "🏷️ 类型",
        "ttl": "⏲️ TTL",
        "class": "📂 类别",
        "target": "🎯 目标",
        "priority": "🔝 优先级",
        
        # Ping
        "ip": "📍 IP地址",
        "location": "🌍 归属地",
        "loss": "📉 丢包率",
        "sent": "📤 发送包数",
        "received": "📥 接收包数",
        "seq": "🔢 序列号"
    }

    TIMEOUT = 10  # Seconds

    def __init__(self, context: Context):
        super().__init__(context)
        self.client = UapiClient("https://uapis.cn")

    # ---------------- WHOIS ----------------
    @filter.command("whois")
    async def whois_cmd(self, event: AstrMessageEvent, domain: str = ""):
        '''查询域名 WHOIS 信息'''
        if not domain:
            yield event.plain_result("请输入域名，例如：/whois google.com")
            return
        result = await self._get_whois(domain)
        
        try:
            node = Node(
                uin=event.message_obj.self_id,
                name="Whois查询结果",
                content=[Plain(result)]
            )
            yield MessageEventResult(message_chain=[node])
        except Exception:
            # Fallback to plain text if forward message fails (e.g. not supported by adapter)
            yield event.plain_result(result)

    @filter.llm_tool(name="get_whois")
    async def get_whois(self, event: AstrMessageEvent, domain: str):
        '''查询域名 WHOIS 信息。
        
        Args:
            domain (str): 域名，例如 "google.com"
        '''
        return await self._get_whois(domain)

    def _format_data(self, data, indent=0):
        """Recursively format data into a readable string."""
        spacing = "  " * indent
        if isinstance(data, dict):
            lines = []
            for key, value in data.items():
                # Skip ping delay/latency related fields, empty/null values, and punycode
                if key in ["min", "avg", "max", "mdev", "time", "id", "punycode"] or value is None or value == "":
                    continue
                    
                translated_key = self.KEY_TRANSLATIONS.get(key.lower(), key)
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
                asyncio.to_thread(self.client.network.get_network_whois, domain=domain, format="json"),
                timeout=self.TIMEOUT
            )
            return self._process_result(result, f"🔍 WHOIS 查询结果 ({domain}):")
        except asyncio.TimeoutError:
            return f"❌ 请求超时，请稍后重试。"
        except UapiError as exc:
            return f"API error: {exc}"
        except Exception as e:
            return f"Error: {e}"

    # ---------------- DNS ----------------
    @filter.command("DNS")
    async def dns_cmd(self, event: AstrMessageEvent, domain: str = ""):
        '''查询域名 DNS 解析记录'''
        if not domain:
            yield event.plain_result("请输入域名，例如：/DNS cn.bing.com")
            return
        result = await self._get_dns(domain)
        yield event.plain_result(result)

    @filter.llm_tool(name="get_dns")
    async def get_dns(self, event: AstrMessageEvent, domain: str, record_type: str = "A"):
        '''查询域名 DNS 解析记录。
        
        Args:
            domain (str): 域名，例如 "cn.bing.com"
            record_type (str): 记录类型，例如 "A", "CNAME", "MX", "TXT", "NS", "AAAA"。默认为 "A"。
        '''
        return await self._get_dns(domain, record_type)

    async def _get_dns(self, domain: str, record_type: str = "A") -> str:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self.client.network.get_network_dns, domain=domain, type=record_type),
                timeout=self.TIMEOUT
            )
            return self._process_result(result, f"🌐 DNS 解析记录 ({domain} - {record_type}):")
        except asyncio.TimeoutError:
            return f"❌ 请求超时，请稍后重试。"
        except UapiError as exc:
            return f"API error: {exc}"
        except Exception as e:
            return f"Error: {e}"


    # ---------------- Ping ----------------
    @filter.command("ping")
    async def ping_cmd(self, event: AstrMessageEvent, host: str = ""):
        '''Ping 主机'''
        if not host:
            yield event.plain_result("请输入主机名或 IP，例如：/ping cn.bing.com")
            return
        result = await self._ping_host(host)
        yield event.plain_result(result)

    @filter.llm_tool(name="ping_host")
    async def ping_host(self, event: AstrMessageEvent, host: str):
        '''Ping 主机检测连通性。
        
        Args:
            host (str): 域名或 IP 地址
        '''
        return await self._ping_host(host)

    async def _ping_host(self, host: str) -> str:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self.client.network.get_network_ping, host=host),
                timeout=self.TIMEOUT
            )
            return self._process_result(result, f"📶 Ping 检测结果 ({host}):")
        except asyncio.TimeoutError:
            return f"❌ 请求超时，请稍后重试。"
        except UapiError as exc:
            return f"API error: {exc}"
        except Exception as e:
            return f"Error: {e}"
