#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""极简 SOCKS5 代理（仅 CONNECT，无认证，远端 DNS）。用于 GitHub Actions 出网回传给本机。"""
import asyncio
import ipaddress
import socket
import struct
import sys

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1080


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(reader, writer):
    try:
        # 握手：VER NMETHODS METHODS...
        head = await reader.readexactly(2)
        if head[0] != 0x05:
            writer.close()
            return
        nmethods = head[1]
        await reader.readexactly(nmethods)
        writer.write(b"\x05\x00")  # 无需认证
        await writer.drain()

        # 请求：VER CMD RSV ATYP ...
        req = await reader.readexactly(4)
        ver, cmd, _rsv, atyp = req
        if cmd != 0x01:  # 只支持 CONNECT
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            writer.close()
            return

        if atyp == 0x01:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode("ascii", "ignore")
        elif atyp == 0x04:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        else:
            writer.close()
            return
        port = struct.unpack("!H", await reader.readexactly(2))[0]

        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15
            )
        except Exception:
            writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)  # 连接被拒
            await writer.drain()
            writer.close()
            return

        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)  # 成功
        await writer.drain()
        await asyncio.gather(pipe(reader, w), pipe(r, writer))
    except Exception:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN_PORT, backlog=512)
    print(f"SOCKS5 listening on 0.0.0.0:{LISTEN_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
