import logging
import socket
import json
import time
import struct
import uuid
from typing import Dict, Any, List, Union, Optional, Tuple
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
)
from enum import Enum
from pydantic import BaseModel


class VariableGlobalGet(BaseModel):
    variable_name: str


class VariableGlobalRename(BaseModel):
    old_name: str
    new_name: str


class VariableLocalRename(BaseModel):
    function_name: str
    old_name: str
    new_name: str


class FunctionDisassemble(BaseModel):
    function_name: str


class FunctionDisassembleCurrent(BaseModel):
    pass


class FunctionDecompile(BaseModel):
    function_name: str


class FunctionDecompileCurrent(BaseModel):
    pass


class FunctionRename(BaseModel):
    old_name: str
    new_name: str


class FunctionCommentAdd(BaseModel):
    function_name: str
    comment: str
    is_repeatable: bool = False


class AddressCommentAdd(BaseModel):
    address: str
    comment: str
    is_repeatable: bool = False


class PseudocodeCommentAdd(BaseModel):
    function_name: str
    line_number: int
    comment: str
    is_repeatable: bool = False


class IDATools(str, Enum):
    VARIABLE_GLOBAL_GET = "ida_variable_global_get"
    VARIABLE_GLOBAL_RENAME = "ida_variable_global_rename"
    VARIABLE_LOCAL_RENAME = "ida_variable_local_rename"
    FUNCTION_DISASSEMBLE = "ida_function_disassemble"
    FUNCTION_DISASSEMBLE_CURRENT = "ida_function_disassemble_current"
    FUNCTION_DECOMPILE = "ida_function_decompile"
    FUNCTION_DECOMPILE_CURRENT = "ida_function_decompile_current"
    FUNCTION_RENAME = "ida_function_rename"
    FUNCTION_COMMENT_ADD = "ida_function_comment_add"
    ADDRESS_COMMENT_ADD = "ida_address_comment_add"
    PSEUDOCODE_COMMENT_ADD = "ida_pseudocode_comment_add"


class IDAProCommunicator:
    def __init__(self, host="localhost", port=5000):
        self.host = host
        self.port = port
        self.sock = None
        self.logger = logging.getLogger(__name__)
        self.connected = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.last_reconnect_time = 0
        self.reconnect_cooldown = 5
        self.request_count = 0

    def connect(self):
        current_time = time.time()
        if (
            current_time - self.last_reconnect_time < self.reconnect_cooldown
            and self.reconnect_attempts > 0
        ):
            self.logger.debug("reconnect cooldown, skip")
            return False

        if self.connected:
            self.disconnect()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            self.connected = True
            self.reconnect_attempts = 0
            self.logger.info(f"connected to IDA Pro ({self.host}:{self.port})")
            return True
        except Exception as e:
            self.last_reconnect_time = current_time
            self.reconnect_attempts += 1
            if self.reconnect_attempts <= self.max_reconnect_attempts:
                self.logger.warning(
                    f"unable to connect to  IDA Pro: {str(e)}. try {self.reconnect_attempts}/{self.max_reconnect_attempts}"
                )
            else:
                self.logger.error(
                    f"tried {self.max_reconnect_attempts} attempts to to connect to IDA Pro: {str(e)}"
                )
            return False

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        self.connected = False

    def ensure_connection(self):
        if not self.connected:
            return self.connect()
        return True

    def send_message(self, data: bytes) -> None:
        length = len(data)
        length_bytes = struct.pack("!I", length)
        self.sock.sendall(length_bytes + data)

    def receive_message(self) -> Optional[bytes]:
        try:
            length_bytes = self.receive_exactly(4)
            if not length_bytes:
                return None

            length = struct.unpack("!I", length_bytes)[0]

            data = self.receive_exactly(length)
            return data
        except Exception as e:
            self.logger.error(f"exception: {str(e)}")
            return None

    def receive_exactly(self, n: int) -> Optional[bytes]:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(min(n - len(data), 4096))
            if not chunk:
                return None
            data += chunk
        return data

    def send_request(self, request_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.ensure_connection():
            return {"error": "not connected to IDA pro"}

        request_id = str(uuid.uuid4())
        self.request_count += 1
        request_count = self.request_count

        request = {
            "id": request_id,
            "count": request_count,
            "type": request_type,
            "data": data,
        }

        self.logger.debug(
            f"send request: {request_id}, type: {request_type}, count: {request_count}"
        )

        try:
            request_json = json.dumps(request).encode("utf-8")
            self.send_message(request_json)

            response_data = self.receive_message()

            if not response_data:
                self.logger.warning("no data received, connection may be closed")
                self.disconnect()
                return {"error": "no response from IDA"}

            try:
                self.logger.debug(f"received length: {len(response_data)}")
                response = json.loads(response_data.decode("utf-8"))

                response_id = response.get("id")
                if response_id != request_id:
                    self.logger.warning(
                        f"response_id/request_id mismatch: {request_id} vs. {response_id}"
                    )

                self.logger.debug(
                    f"response: id={response.get('id')}, count={response.get('count')}"
                )

                if not isinstance(response, dict):
                    self.logger.error(f"response is not a dict: {type(response)}")
                    return {"error": f"expected dict, got: {type(response).__name__}"}

                return response
            except json.JSONDecodeError as e:
                self.logger.error(f"unable to parse JSON: {str(e)}")
                return {"error": f"JSON parse error: {str(e)}"}

        except Exception as e:
            self.logger.error(f"IDA pro communication error: {str(e)}")
            self.disconnect()
            return {"error": str(e)}

    def ping(self):
        response = self.send_request("ping", {})
        return response.get("status") == "pong"


class IDAProFunctions:
    def __init__(self, communicator):
        self.communicator = communicator
        self.logger = logging.getLogger(__name__)

    def function_disassemble(self, function_name: str) -> str:
        try:
            response = self.communicator.send_request(
                "get_function_assembly", {"function_name": function_name}
            )

            if "error" in response:
                return f"Error retrieving assembly for function '{function_name}': {response['error']}"

            assembly = response.get("assembly")
            if assembly is None:
                return (
                    f"Error: No assembly data returned for function '{function_name}'"
                )
            if not isinstance(assembly, str):
                self.logger.warning(
                    f"got type {type(assembly).__name__}，attempting conversion"
                )
                assembly = str(assembly)

            return f"Assembly code for function '{function_name}':\n{assembly}"
        except Exception as e:
            self.logger.error(f"error: {str(e)}", exc_info=True)
            return f"Error retrieving assembly for function '{function_name}': {str(e)}"

    def function_decompile(self, function_name: str) -> str:
        try:
            response = self.communicator.send_request(
                "function_decompile", {"function_name": function_name}
            )

            self.logger.debug(f"反编译响应: {response}")

            if "error" in response:
                return f"Error retrieving decompiled code for function '{function_name}': {response['error']}"

            decompiled_code = response.get("decompiled_code")

            if decompiled_code is None:
                return (
                    f"Error: No decompiled code returned for function '{function_name}'"
                )

            actual_type = type(decompiled_code).__name__
            self.logger.debug(f"the decompiled code type is: {actual_type}")

            if not isinstance(decompiled_code, str):
                self.logger.warning(
                    f"expected string, got {actual_type}, attempting conversion"
                )
                try:
                    decompiled_code = str(decompiled_code)
                except Exception as e:
                    return f"Error: Failed to convert decompiled code from {actual_type} to string: {str(e)}"

            return f"Decompiled code for function '{function_name}':\n{decompiled_code}"
        except Exception as e:
            self.logger.error(f"error: {str(e)}", exc_info=True)
            return f"Error retrieving decompiled code for function '{function_name}': {str(e)}"

    def variable_global_get(self, variable_name: str) -> str:
        try:
            response = self.communicator.send_request(
                "variable_global_get", {"variable_name": variable_name}
            )

            if "error" in response:
                return f"Error retrieving global variable '{variable_name}': {response['error']}"

            variable_info = response.get("variable_info")

            if variable_info is None:
                return f"Error: No variable info returned for '{variable_name}'"
            if not isinstance(variable_info, str):
                self.logger.warning(
                    f"variable information is not a string, got {type(variable_info).__name__}, attempting conversion.."
                )
                try:
                    if isinstance(variable_info, dict):
                        variable_info = json.dumps(variable_info, indent=2)
                    else:
                        variable_info = str(variable_info)
                except Exception as e:
                    return f"Error: Failed to convert variable info to string: {str(e)}"

            return f"Global variable '{variable_name}':\n{variable_info}"
        except Exception as e:
            self.logger.error(f"error: {str(e)}", exc_info=True)
            return f"Error retrieving global variable '{variable_name}': {str(e)}"

    def function_disasssemble_current(self) -> str:
        try:
            response = self.communicator.send_request(
                "function_disasssemble_current", {}
            )

            if "error" in response:
                return f"Error retrieving assembly for current function: {response['error']}"

            assembly = response.get("assembly")
            function_name = response.get("function_name", "Current function")

            if assembly is None:
                return f"Error: No assembly data returned for current function"
            if not isinstance(assembly, str):
                self.logger.warning(
                    f"expected string, got {type(assembly).__name__}，attempting conversion.."
                )
                assembly = str(assembly)

            return f"Assembly code for function '{function_name}':\n{assembly}"
        except Exception as e:
            self.logger.error(
                f"error retrieving assembly for current function: {str(e)}",
                exc_info=True,
            )
            return f"Error retrieving assembly for current function: {str(e)}"

    def function_decompile_current(self) -> str:
        try:
            response = self.communicator.send_request("function_decompile_current", {})

            if "error" in response:
                return f"Error retrieving decompiled code for current function: {response['error']}"

            decompiled_code = response.get("decompiled_code")
            function_name = response.get("function_name", "Current function")

            if decompiled_code is None:
                return f"Error: No decompiled code returned for current function"

            if not isinstance(decompiled_code, str):
                self.logger.warning(
                    f"expected string, got {type(decompiled_code).__name__}, attempting conversion.."
                )
                try:
                    decompiled_code = str(decompiled_code)
                except Exception as e:
                    return f"Error: Failed to convert decompiled code: {str(e)}"

            return f"Decompiled code for function '{function_name}':\n{decompiled_code}"
        except Exception as e:
            self.logger.error(
                f"error retrieving decompiled code for current function: {str(e)}",
                exc_info=True,
            )
            return f"Error retrieving decompiled code for current function: {str(e)}"

    def variable_local_rename(
        self, function_name: str, old_name: str, new_name: str
    ) -> str:
        try:
            response = self.communicator.send_request(
                "variable_local_rename",
                {
                    "function_name": function_name,
                    "old_name": old_name,
                    "new_name": new_name,
                },
            )

            if "error" in response:
                return f"Error renaming local variable from '{old_name}' to '{new_name}' in function '{function_name}': {response['error']}"

            success = response.get("success", False)
            message = response.get("message", "")

            if success:
                return f"Successfully renamed local variable from '{old_name}' to '{new_name}' in function '{function_name}': {message}"
            else:
                return f"Failed to rename local variable from '{old_name}' to '{new_name}' in function '{function_name}': {message}"
        except Exception as e:
            self.logger.error(f"error renaming local variable: {str(e)}", exc_info=True)
            return f"Error renaming local variable from '{old_name}' to '{new_name}' in function '{function_name}': {str(e)}"

    def variable_global_rename(self, old_name: str, new_name: str) -> str:
        try:
            response = self.communicator.send_request(
                "variable_global_rename", {"old_name": old_name, "new_name": new_name}
            )

            if "error" in response:
                return f"Error renaming global variable from '{old_name}' to '{new_name}': {response['error']}"

            success = response.get("success", False)
            message = response.get("message", "")

            if success:
                return f"Successfully renamed global variable from '{old_name}' to '{new_name}': {message}"
            else:
                return f"Failed to rename global variable from '{old_name}' to '{new_name}': {message}"
        except Exception as e:
            self.logger.error(
                f"error renaming global variable: {str(e)}", exc_info=True
            )
            return f"Error renaming global variable from '{old_name}' to '{new_name}': {str(e)}"

    def function_rename(self, old_name: str, new_name: str) -> str:
        try:
            response = self.communicator.send_request(
                "function_rename", {"old_name": old_name, "new_name": new_name}
            )

            if "error" in response:
                return f"Error renaming function from '{old_name}' to '{new_name}': {response['error']}"

            success = response.get("success", False)
            message = response.get("message", "")

            if success:
                return f"Successfully renamed function from '{old_name}' to '{new_name}': {message}"
            else:
                return f"Failed to rename function from '{old_name}' to '{new_name}': {message}"
        except Exception as e:
            self.logger.error(f"error renaming function: {str(e)}", exc_info=True)
            return (
                f"Error renaming function from '{old_name}' to '{new_name}': {str(e)}"
            )

    def function_comment_add(
        self, function_name: str, comment: str, is_repeatable: bool = False
    ) -> str:
        try:
            response = self.communicator.send_request(
                "function_comment_add",
                {
                    "function_name": function_name,
                    "comment": comment,
                    "is_repeatable": is_repeatable,
                },
            )

            if "error" in response:
                return f"Error adding comment to function '{function_name}': {response['error']}"

            success = response.get("success", False)
            message = response.get("message", "")

            if success:
                comment_type = "repeatable" if is_repeatable else "regular"
                return f"Successfully added {comment_type} comment to function '{function_name}': {message}"
            else:
                return f"Failed to add comment to function '{function_name}': {message}"
        except Exception as e:
            self.logger.error(
                f"error adding function annotation: {str(e)}", exc_info=True
            )
            return f"Error adding comment to function '{function_name}': {str(e)}"

    def address_comment_add(
        self, address: str, comment: str, is_repeatable: bool = False
    ) -> str:
        try:
            response = self.communicator.send_request(
                "address_comment_add",
                {
                    "address": address,
                    "comment": comment,
                    "is_repeatable": is_repeatable,
                },
            )

            if "error" in response:
                return (
                    f"Error adding comment at address '{address}': {response['error']}"
                )

            success = response.get("success", False)
            message = response.get("message", "")

            if success:
                comment_type = "repeatable" if is_repeatable else "regular"
                return f"Successfully added {comment_type} comment at address '{address}': {message}"
            else:
                return f"Failed to add comment at address '{address}': {message}"
        except Exception as e:
            self.logger.error(f"error adding comment: {str(e)}", exc_info=True)
            return f"Error adding comment at address '{address}': {str(e)}"

    def pseudocode_comment_add(
        self,
        function_name: str,
        line_number: int,
        comment: str,
        is_repeatable: bool = False,
    ) -> str:
        try:
            response = self.communicator.send_request(
                "pseudocode_comment_add",
                {
                    "function_name": function_name,
                    "line_number": line_number,
                    "comment": comment,
                    "is_repeatable": is_repeatable,
                },
            )

            if "error" in response:
                return f"Error adding comment to line {line_number} in function '{function_name}': {response['error']}"

            success = response.get("success", False)
            message = response.get("message", "")

            if success:
                comment_type = "repeatable" if is_repeatable else "regular"
                return f"Successfully added {comment_type} comment to line {line_number} in function '{function_name}': {message}"
            else:
                return f"Failed to add comment to line {line_number} in function '{function_name}': {message}"
        except Exception as e:
            self.logger.error(
                f"error while adding pseudocode line comment: {str(e)}", exc_info=True
            )
            return f"Error adding comment to line {line_number} in function '{function_name}': {str(e)}"


async def serve() -> None:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    server = Server("mcp-ida")

    ida_communicator = IDAProCommunicator()
    logger.info("attempting to connect to IDA plugin..")

    if ida_communicator.connect():
        logger.info("successfully connected to IDA plugin")
    else:
        logger.warning(
            "initial connection to IDA plugin failed, will retry when requested"
        )

    ida_functions = IDAProFunctions(ida_communicator)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = [
            [
                IDATools.VARIABLE_GLOBAL_GET,
                "Get information about a global variable by name",
                VariableGlobalGet,
            ],
            [
                IDATools.VARIABLE_GLOBAL_RENAME,
                "Rename a global variable in the IDA database",
                VariableGlobalRename,
            ],
            [
                IDATools.VARIABLE_LOCAL_RENAME,
                "Rename a local variable within a function in the IDA database",
                VariableLocalRename,
            ],
            [
                IDATools.FUNCTION_DISASSEMBLE,
                "Get assembly code for a function by name",
                FunctionDisassemble,
            ],
            [
                IDATools.FUNCTION_DISASSEMBLE_CURRENT,
                "Get assembly code for the function at the current cursor position",
                FunctionDisassembleCurrent,
            ],
            [
                IDATools.FUNCTION_DECOMPILE,
                "Get decompiled pseudocode for a function by name",
                FunctionDecompile,
            ],
            [
                IDATools.FUNCTION_DECOMPILE_CURRENT,
                "Get decompiled pseudocode for the function at the current cursor position",
                FunctionDecompileCurrent,
            ],
            [
                IDATools.FUNCTION_RENAME,
                "Rename a function in the IDA database",
                FunctionRename,
            ],
            [
                IDATools.FUNCTION_COMMENT_ADD,
                "Add a comment to a function in the IDA database",
                FunctionCommentAdd,
            ],
            [
                IDATools.ADDRESS_COMMENT_ADD,
                "Add a comment at a specific address in the IDA database",
                AddressCommentAdd,
            ],
            [
                IDATools.PSEUDOCODE_COMMENT_ADD,
                "Add a comment to a specific line in the function's decompiled pseudocode",
                PseudocodeCommentAdd,
            ],
        ]

        tools_ret = []

        for tool in tools:
            tool_ret = Tool(
                name=tool[0],
                description=tool[1],
                inputSchema=tool[2].schema(),
            )
            tools_ret.append(tool_ret)
        return tools_ret

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> List[TextContent]:
        if not ida_communicator.connected and not ida_communicator.ensure_connection():
            return [
                TextContent(
                    type="text",
                    text=f"Error: Cannot connect to IDA Pro plugin. Please ensure the plugin is running.",
                )
            ]

        if name not in IDATools.__members__.values():
            return [TextContent(type="text", text=f"Error: Unknown tool '{name}'")]

        ida_tool_lut = {
            IDATools.VARIABLE_GLOBAL_GET: [
                ida_functions.variable_global_get,
                ["variable_name"],
            ],
            IDATools.VARIABLE_GLOBAL_RENAME: [
                ida_functions.variable_global_rename,
                ["old_name", "new_name"],
            ],
            IDATools.VARIABLE_LOCAL_RENAME: [
                ida_functions.variable_local_rename,
                ["function_name", "old_name", "new_name"],
            ],
            IDATools.FUNCTION_DISASSEMBLE: [
                ida_functions.function_disassemble,
                ["function_name"],
            ],
            IDATools.FUNCTION_DISASSEMBLE_CURRENT: [
                ida_functions.function_disasssemble_current,
                [],
            ],
            IDATools.FUNCTION_DECOMPILE: [
                ida_functions.function_decompile,
                ["function_name"],
            ],
            IDATools.FUNCTION_DECOMPILE_CURRENT: [
                ida_functions.function_decompile_current,
                [],
            ],
            IDATools.FUNCTION_RENAME: [
                ida_functions.function_rename,
                ["old_name", "new_name"],
            ],
            IDATools.FUNCTION_COMMENT_ADD: [
                ida_functions.function_comment_add,
                ["function_name", "comment", "is_repeatable"],
            ],
            IDATools.ADDRESS_COMMENT_ADD: [
                ida_functions.address_comment_add,
                ["address", "comment", "is_repeatable"],
            ],
            IDATools.PSEUDOCODE_COMMENT_ADD: [
                ida_functions.pseudocode_comment_add,
                ["function_name", "line_number", "comment", "is_repeatable"],
            ],
        }

        ida_function, ida_function_args = ida_tool_lut[name]

        try:
            result = ida_function(**{k: arguments[k] for k in ida_function_args})
            return [TextContent(type="text", text=result)]
        except Exception as e:
            logger.error(f"tool invocation error: {str(e)}", exc_info=True)
            return [TextContent(type="text", text=f"Error executing {name}: {str(e)}")]

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)
