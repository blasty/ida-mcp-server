import logging
import socket
import json
from typing import Dict, Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
)
from enum import Enum
from pydantic import BaseModel

class GetFunctionAssembly(BaseModel):
    function_name: str

class GetFunctionDecompiled(BaseModel):
    function_name: str

class GetGlobalVariable(BaseModel):
    variable_name: str

class IDATools(str, Enum):
    GET_FUNCTION_ASSEMBLY = "ida_get_function_assembly"
    GET_FUNCTION_DECOMPILED = "ida_get_function_decompiled"
    GET_GLOBAL_VARIABLE = "ida_get_global_variable"

# IDA Pro通信处理器
class IDAProCommunicator:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.sock = None
        self.logger = logging.getLogger(__name__)
    
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.logger.info(f"Connected to IDA Pro at {self.host}:{self.port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to IDA Pro: {str(e)}")
            return False
    
    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def send_request(self, request_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.sock:
            if not self.connect():
                return {"error": "Not connected to IDA Pro"}
        
        request = {
            "type": request_type,
            "data": data
        }
        
        try:
            # 发送请求
            self.sock.sendall(json.dumps(request).encode('utf-8'))
            
            # 读取响应
            response_data = b""
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if len(chunk) < 4096:  # 简单判断接收完成
                    break
            
            # 解析响应
            response = json.loads(response_data.decode('utf-8'))
            return response
        except Exception as e:
            self.logger.error(f"Error communicating with IDA Pro: {str(e)}")
            return {"error": str(e)}

# 实际的IDA Pro功能实现
class IDAProFunctions:
    def __init__(self):
        self.communicator = IDAProCommunicator()
        
    def get_function_assembly(self, function_name: str) -> str:
        response = self.communicator.send_request(
            "get_function_assembly", 
            {"function_name": function_name}
        )
        
        if "error" in response:
            return f"Error retrieving assembly for function '{function_name}': {response['error']}"
        
        return f"Assembly code for function '{function_name}':\n{response.get('assembly', 'Not found')}"
    
    def get_function_decompiled(self, function_name: str) -> str:
        response = self.communicator.send_request(
            "get_function_decompiled", 
            {"function_name": function_name}
        )
        
        if "error" in response:
            return f"Error retrieving decompiled code for function '{function_name}': {response['error']}"
        
        return f"Decompiled code for function '{function_name}':\n{response.get('decompiled_code', 'Not found')}"
    
    def get_global_variable(self, variable_name: str) -> str:
        response = self.communicator.send_request(
            "get_global_variable", 
            {"variable_name": variable_name}
        )
        
        if "error" in response:
            return f"Error retrieving global variable '{variable_name}': {response['error']}"
        
        return f"Global variable '{variable_name}':\n{response.get('variable_info', 'Not found')}"

async def serve() -> None:
    logger = logging.getLogger(__name__)
    server = Server("mcp-ida")
    ida_functions = IDAProFunctions()

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=IDATools.GET_FUNCTION_ASSEMBLY,
                description="Get assembly code for a function by name",
                inputSchema=GetFunctionAssembly.schema(),
            ),
            Tool(
                name=IDATools.GET_FUNCTION_DECOMPILED,
                description="Get decompiled pseudocode for a function by name",
                inputSchema=GetFunctionDecompiled.schema(),
            ),
            Tool(
                name=IDATools.GET_GLOBAL_VARIABLE,
                description="Get information about a global variable by name",
                inputSchema=GetGlobalVariable.schema(),
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        match name:
            case IDATools.GET_FUNCTION_ASSEMBLY:
                assembly = ida_functions.get_function_assembly(arguments["function_name"])
                return [TextContent(
                    type="text",
                    text=assembly
                )]

            case IDATools.GET_FUNCTION_DECOMPILED:
                decompiled = ida_functions.get_function_decompiled(arguments["function_name"])
                return [TextContent(
                    type="text",
                    text=decompiled
                )]

            case IDATools.GET_GLOBAL_VARIABLE:
                variable_info = ida_functions.get_global_variable(arguments["variable_name"])
                return [TextContent(
                    type="text",
                    text=variable_info
                )]

            case _:
                raise ValueError(f"Unknown tool: {name}")

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)
