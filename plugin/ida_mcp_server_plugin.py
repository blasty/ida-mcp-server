import idaapi
import idautils
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_name
import ida_segment
import ida_lines
import idc
import json
import socket
import struct
import threading
import traceback
import time

from errno import EBADF

PLUGIN_NAME = "IDA MCP Server"
PLUGIN_HOTKEY = "Ctrl-Alt-M"
PLUGIN_VERSION = "1.0"
PLUGIN_AUTHOR = "IDA MCP"

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000


class IDASyncWrapper(object):
    def __init__(self):
        self.result = None

    def __call__(self, func, *args, **kwargs):
        self.result = func(*args, **kwargs)
        return 1


class IDACommunicator:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self):
        pass


class IDAMCPServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None
        self.client_counter = 0

    def start(self):
        if self.running:
            print("MCP Server already running")
            return False

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            self.running = True
            self.thread = threading.Thread(target=self.server_loop)
            self.thread.daemon = True
            self.thread.start()

            print(f"MCP Server started on {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Failed to start MCP Server: {str(e)}")
            traceback.print_exc()
            return False

    def stop(self):
        if not self.running:
            print("MCP Server is not running, no need to stop")
            return

        print("Stopping MCP Server...")
        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"Error closing server socket: {str(e)}")
            self.server_socket = None

        if self.thread:
            try:
                self.thread.join(2.0)
            except Exception as e:
                print(f"Error joining server thread: {str(e)}")
            self.thread = None

        print("MCP Server stopped")

    def send_message(self, client_socket, data: bytes) -> None:
        length = len(data)
        length_bytes = struct.pack("!I", length)
        client_socket.sendall(length_bytes + data)

    def receive_message(self, client_socket) -> bytes:
        length_bytes = self.receive_exactly(client_socket, 4)
        if not length_bytes:
            raise ConnectionError("truncated read.")

        length = struct.unpack("!I", length_bytes)[0]
        data = self.receive_exactly(client_socket, length)
        return data

    def receive_exactly(self, client_socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = client_socket.recv(min(n - len(data), 4096))
            if not chunk:
                raise ConnectionError("connection closed. no data received.")
            data += chunk
        return data

    def server_loop(self):
        print("Server loop started")
        while self.running:
            try:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.client_counter += 1
                    client_id = self.client_counter
                    print(f"Client #{client_id} connected from {client_address}")

                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.running:
                        if e.errno == EBADF:
                            print("Server socket was closed")
                            break
                        print(f"Socket error: {str(e)}")
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {str(e)}")
                        traceback.print_exc()
            except Exception as e:
                if self.running:
                    print(f"Error in server loop: {str(e)}")
                    traceback.print_exc()
                time.sleep(1)

        print("Server loop ended")

    def handle_client(self, client_socket, client_id):
        request_noarg_lut = {
            "function_disassemble_current": self.function_disassemble_current,
            "function_decompile_current": self.function_decompile_current,
        }

        request_arg_lut = {
            "function_disassemble": self.function_disassemble,
            "function_decompile": self.function_decompile,
            "variable_global_get": self.variable_global_get,
            "variable_global_rename": self.variable_global_rename,
            "function_rename": self.function_rename,
            "address_comment_add": self.address_comment_add,
            "variable_local_rename": self.variable_local_rename,
            "function_comment_add": self.function_comment_add,
            "pseudocode_comment_add": self.pseudocode_comment_add,
            "view_refresh": self.view_refresh,
        }

        try:
            client_socket.settimeout(30)
            while self.running:
                try:
                    data = self.receive_message(client_socket)

                    request = json.loads(data.decode("utf-8"))
                    request_type = request.get("type")
                    request_data = request.get("data", {})
                    request_id = request.get("id", "unknown")
                    request_count = request.get("count", -1)

                    print(
                        f"Client #{client_id} request: {request_type}, ID: {request_id}, Count: {request_count}"
                    )

                    response = {
                        "id": request_id,
                        "count": request_count,
                    }

                    if request_type == "ping":
                        response["status"] = "pong"
                    elif request_type in request_noarg_lut:
                        result = request_noarg_lut[request_type]()
                        response.update(result)
                    elif request_type in request_arg_lut:
                        result = request_arg_lut[request_type](request_data)
                        response.update(result)
                    else:
                        response["error"] = f"Unknown request type: {request_type}"

                    if not isinstance(response, dict):
                        print(
                            f"Response is not a dictionary: {type(response).__name__}"
                        )
                        response = {
                            "id": request_id,
                            "count": request_count,
                            "error": f"Internal server error: response is not a dictionary but {type(response).__name__}",
                        }

                    for key, value in list(response.items()):
                        if value is None:
                            response[key] = "null"
                        elif not isinstance(
                            value, (str, int, float, bool, list, dict, tuple)
                        ):
                            print(
                                f"Response key '{key}' has non-serializable type: {type(value).__name__}"
                            )
                            response[key] = str(value)

                    response_json = json.dumps(response).encode("utf-8")
                    self.send_message(client_socket, response_json)
                    print(
                        f"Sent response to client #{client_id}, ID: {request_id}, Count: {request_count}"
                    )

                except ConnectionError as e:
                    print(f"Connection with client #{client_id} lost: {str(e)}")
                    return
                except socket.timeout:
                    print(f"Socket timeout with client #{client_id}")
                    continue
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON request from client #{client_id}: {str(e)}")
                    try:
                        response = {"error": f"Invalid JSON request: {str(e)}"}
                        self.send_message(
                            client_socket, json.dumps(response).encode("utf-8")
                        )
                    except:
                        print(f"Failed to send error response to client #{client_id}")
                except Exception as e:
                    print(
                        f"Error processing request from client #{client_id}: {str(e)}"
                    )
                    traceback.print_exc()
                    try:
                        response = {"error": str(e)}
                        self.send_message(
                            client_socket, json.dumps(response).encode("utf-8")
                        )
                    except:
                        print(f"Failed to send error response to client #{client_id}")

        except Exception as e:
            print(f"Error handling client #{client_id}: {str(e)}")
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except:
                pass
            print(f"Client #{client_id} connection closed")

    def function_disassemble(self, data):
        function_name = data.get("function_name", "")

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(self._function_disassemble_impl, function_name),
            idaapi.MFF_READ,
        )
        return wrapper.result

    def _function_disassemble_impl(self, function_name):
        try:
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}

            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"error": f"Invalid function at {hex(func_addr)}"}

            assembly_lines = []
            for instr_addr in idautils.FuncItems(func_addr):
                disasm = idc.GetDisasm(instr_addr)
                assembly_lines.append(f"{hex(instr_addr)}: {disasm}")

            if not assembly_lines:
                return {"error": "No assembly instructions found"}

            return {"assembly": "\n".join(assembly_lines)}
        except Exception as e:
            print(f"Error getting function assembly: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}

    def function_decompile(self, data):
        function_name = data.get("function_name", "")

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(self._function_decompile_impl, function_name),
            idaapi.MFF_READ,
        )
        return wrapper.result

    def _function_decompile_impl(self, function_name):
        try:
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}

            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"error": f"Invalid function at {hex(func_addr)}"}

            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Hex-Rays decompiler not available"}

            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"error": "Failed to decompile function"}

            sv = cfunc.get_pseudocode()
            if not sv:
                return {"error": "No pseudocode generated"}

            decompiled_text = []

            for sline in sv:
                line_text = ida_lines.tag_remove(sline.line)
                if line_text is not None:
                    decompiled_text.append(line_text)

            if not decompiled_text:
                return {"decompiled_code": "// No code content available"}

            result = "\n".join(decompiled_text)

            print(
                f"Decompiled text type: {type(result).__name__}, length: {len(result)}"
            )

            return {"decompiled_code": result}
        except Exception as e:
            print(f"Error decompiling function: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}

    def variable_global_get(self, data):
        variable_name = data.get("variable_name", "")

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(self._variable_global_get_impl, variable_name),
            idaapi.MFF_READ,
        )
        return wrapper.result

    def _variable_global_get_impl(self, variable_name):
        try:
            var_addr = ida_name.get_name_ea(0, variable_name)
            if var_addr == idaapi.BADADDR:
                return {"error": f"Global variable '{variable_name}' not found"}

            segment = ida_segment.getseg(var_addr)
            if not segment:
                return {"error": f"No segment found for address {hex(var_addr)}"}

            segment_name = ida_segment.get_segm_name(segment)
            segment_class = ida_segment.get_segm_class(segment)

            tinfo = idaapi.tinfo_t()
            guess_type = idaapi.guess_tinfo(tinfo, var_addr)
            type_str = tinfo.get_type_name() if guess_type else "unknown"

            size = ida_bytes.get_item_size(var_addr)
            if size <= 0:
                size = 8

            value = None
            if size == 1:
                value = ida_bytes.get_byte(var_addr)
            elif size == 2:
                value = ida_bytes.get_word(var_addr)
            elif size == 4:
                value = ida_bytes.get_dword(var_addr)
            elif size == 8:
                value = ida_bytes.get_qword(var_addr)

            var_info = {
                "name": variable_name,
                "address": hex(var_addr),
                "segment": segment_name,
                "segment_class": segment_class,
                "type": type_str,
                "size": size,
                "value": hex(value) if value is not None else "N/A",
            }

            if ida_bytes.is_strlit(ida_bytes.get_flags(var_addr)):
                str_value = idc.get_strlit_contents(var_addr, -1, 0)
                if str_value:
                    try:
                        var_info["string_value"] = str_value.decode(
                            "utf-8", errors="replace"
                        )
                    except:
                        var_info["string_value"] = str(str_value)

            return {"variable_info": json.dumps(var_info, indent=2)}
        except Exception as e:
            print(f"Error getting global variable: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}

    def function_disassemble_current(self):
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(self._function_disassemble_current_impl), idaapi.MFF_READ
        )
        return wrapper.result

    def _function_disassemble_current_impl(self):
        try:
            current_addr = idaapi.get_screen_ea()
            if current_addr == idaapi.BADADDR:
                return {"error": "Invalid cursor position"}

            func = ida_funcs.get_func(current_addr)
            if not func:
                return {
                    "error": f"No function found at current position {hex(current_addr)}"
                }

            func_name = ida_funcs.get_func_name(func.start_ea)

            assembly_lines = []
            for instr_addr in idautils.FuncItems(func.start_ea):
                disasm = idc.GetDisasm(instr_addr)
                assembly_lines.append(f"{hex(instr_addr)}: {disasm}")

            if not assembly_lines:
                return {"error": "No assembly instructions found"}

            return {
                "function_name": func_name,
                "function_address": hex(func.start_ea),
                "assembly": "\n".join(assembly_lines),
            }
        except Exception as e:
            print(f"Error getting current function assembly: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}

    def function_decompile_current(self):
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(self._function_decompile_current_impl), idaapi.MFF_READ
        )
        return wrapper.result

    def _function_decompile_current_impl(self):
        try:
            current_addr = idaapi.get_screen_ea()
            if current_addr == idaapi.BADADDR:
                return {"error": "Invalid cursor position"}

            func = ida_funcs.get_func(current_addr)
            if not func:
                return {
                    "error": f"No function found at current position {hex(current_addr)}"
                }

            func_name = ida_funcs.get_func_name(func.start_ea)

            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Hex-Rays decompiler not available"}

            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"error": "Failed to decompile function"}

            sv = cfunc.get_pseudocode()
            if not sv:
                return {"error": "No pseudocode generated"}

            decompiled_text = []

            for sline in sv:
                line_text = ida_lines.tag_remove(sline.line)
                if line_text is not None:
                    decompiled_text.append(line_text)

            if not decompiled_text:
                return {"decompiled_code": "// No code content available"}

            result = "\n".join(decompiled_text)

            print(
                f"Current function decompiled text type: {type(result).__name__}, length: {len(result)}"
            )

            return {
                "function_name": func_name,
                "function_address": hex(func.start_ea),
                "decompiled_code": result,
            }
        except Exception as e:
            print(f"Error decompiling current function: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}

    def variable_global_rename(self, data):
        old_name = data.get("old_name", "")
        new_name = data.get("new_name", "")

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(self._variable_global_rename_impl, old_name, new_name),
            idaapi.MFF_WRITE,
        )
        return wrapper.result

    def _variable_global_rename_impl(self, old_name, new_name):
        try:
            var_addr = ida_name.get_name_ea(0, old_name)
            if var_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Variable '{old_name}' not found"}

            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {
                    "success": False,
                    "message": f"Name '{new_name}' is already in use",
                }

            if not ida_name.set_name(var_addr, new_name):
                return {
                    "success": False,
                    "message": f"Failed to rename variable, possibly due to invalid name format or other IDA restrictions",
                }

            self._view_refresh_impl()

            return {
                "success": True,
                "message": f"Variable renamed from '{old_name}' to '{new_name}' at address {hex(var_addr)}",
            }

        except Exception as e:
            print(f"Error renaming variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    def function_rename(self, data):
        old_name = data.get("old_name", "")
        new_name = data.get("new_name", "")

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(self._function_rename_impl, old_name, new_name),
            idaapi.MFF_WRITE,
        )
        return wrapper.result

    def _function_rename_impl(self, old_name, new_name):
        try:
            func_addr = ida_name.get_name_ea(0, old_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{old_name}' not found"}

            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{old_name}' is not a function"}

            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {
                    "success": False,
                    "message": f"Name '{new_name}' is already in use",
                }

            if not ida_name.set_name(func_addr, new_name):
                return {
                    "success": False,
                    "message": f"Failed to rename function, possibly due to invalid name format or other IDA restrictions",
                }

            self._view_refresh_impl()

            return {
                "success": True,
                "message": f"Function renamed from '{old_name}' to '{new_name}' at address {hex(func_addr)}",
            }

        except Exception as e:
            print(f"Error renaming function: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    def address_comment_add(self, data):
        address = data.get("address", "")
        comment = data.get("comment", "")
        is_repeatable = data.get("is_repeatable", False)

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(
                self._address_comment_add_impl, address, comment, is_repeatable
            ),
            idaapi.MFF_WRITE,
        )
        return wrapper.result

    def _address_comment_add_impl(self, address, comment, is_repeatable):
        try:
            if isinstance(address, str):
                if address.startswith("0x"):
                    addr = int(address, 16)
                else:
                    try:
                        addr = int(address, 16)
                    except ValueError:
                        try:
                            addr = int(address)
                        except ValueError:
                            return {
                                "success": False,
                                "message": f"Invalid address format: {address}",
                            }
            else:
                addr = address

            if addr == idaapi.BADADDR or not ida_bytes.is_loaded(addr):
                return {
                    "success": False,
                    "message": f"Invalid or unloaded address: {hex(addr)}",
                }

            result = idc.set_cmt(addr, comment, is_repeatable)
            if result:
                self._view_refresh_impl()
                comment_type = "repeatable" if is_repeatable else "regular"
                return {
                    "success": True,
                    "message": f"Added {comment_type} comment at address {hex(addr)}",
                }
            else:
                return {
                    "success": False,
                    "message": f"Failed to add comment at address {hex(addr)}",
                }

        except Exception as e:
            print(f"Error adding comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    def variable_local_rename(self, data):
        function_name = data.get("function_name", "")
        old_name = data.get("old_name", "")
        new_name = data.get("new_name", "")

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(
                self._variable_local_rename_impl, function_name, old_name, new_name
            ),
            idaapi.MFF_WRITE,
        )
        return wrapper.result

    def _variable_local_rename_impl(self, function_name, old_name, new_name):
        try:
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not old_name:
                return {
                    "success": False,
                    "message": "Old variable name cannot be empty",
                }
            if not new_name:
                return {
                    "success": False,
                    "message": "New variable name cannot be empty",
                }

            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {
                    "success": False,
                    "message": f"Function '{function_name}' not found",
                }

            func = ida_funcs.get_func(func_addr)
            if not func:
                return {
                    "success": False,
                    "message": f"'{function_name}' is not a function",
                }

            if not ida_hexrays.init_hexrays_plugin():
                return {
                    "success": False,
                    "message": "Hex-Rays decompiler is not available",
                }

            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {
                    "success": False,
                    "message": f"Failed to decompile function '{function_name}'",
                }

            found = False
            renamed = False
            lvar = None

            lvars = cfunc.get_lvars()
            for i in range(lvars.size()):
                v = lvars[i]
                if v.name == old_name:
                    lvar = v
                    found = True
                    break

            if not found:
                return {
                    "success": False,
                    "message": f"Local variable '{old_name}' not found in function '{function_name}'",
                }

            if ida_hexrays.rename_lvar(cfunc.entry_ea, lvar.name, new_name):
                renamed = True

            if renamed:
                self._view_refresh_impl()
                return {
                    "success": True,
                    "message": f"Local variable renamed from '{old_name}' to '{new_name}' in function '{function_name}'",
                }
            else:
                return {
                    "success": False,
                    "message": f"Failed to rename local variable from '{old_name}' to '{new_name}', possibly due to invalid name format or other IDA restrictions",
                }

        except Exception as e:
            print(f"Error renaming local variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    def function_comment_add(self, data):
        function_name = data.get("function_name", "")
        comment = data.get("comment", "")
        is_repeatable = data.get("is_repeatable", False)

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(
                self._function_comment_add_impl, function_name, comment, is_repeatable
            ),
            idaapi.MFF_WRITE,
        )
        return wrapper.result

    def _function_comment_add_impl(self, function_name, comment, is_repeatable):
        try:
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not comment:
                comment = ""

            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {
                    "success": False,
                    "message": f"Function '{function_name}' not found",
                }

            func = ida_funcs.get_func(func_addr)
            if not func:
                return {
                    "success": False,
                    "message": f"'{function_name}' is not a function",
                }

            result = idc.set_func_cmt(func_addr, comment, is_repeatable)

            if result:
                self._view_refresh_impl()
                comment_type = "repeatable" if is_repeatable else "regular"
                return {
                    "success": True,
                    "message": f"Added {comment_type} comment to function '{function_name}'",
                }
            else:
                return {
                    "success": False,
                    "message": f"Failed to add comment to function '{function_name}'",
                }

        except Exception as e:
            print(f"Error adding function comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    def pseudocode_comment_add(self, data):
        """Add a comment to a specific line in the function's decompiled pseudocode"""
        function_name = data.get("function_name", "")
        line_number = data.get("line_number", 0)
        comment = data.get("comment", "")
        is_repeatable = data.get("is_repeatable", False)

        wrapper = IDASyncWrapper()
        idaapi.execute_sync(
            lambda: wrapper(
                self._pseudocode_comment_add_impl,
                function_name,
                line_number,
                comment,
                is_repeatable,
            ),
            idaapi.MFF_WRITE,
        )
        return wrapper.result

    def _pseudocode_comment_add_impl(
        self, function_name, line_number, comment, is_repeatable
    ):
        """
        Implement adding a comment to a specific line of pseudocode in the IDA main thread
        Warning: incomplete implementation, only works for simple cases
        """
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if line_number <= 0:
                return {"success": False, "message": "Line number must be positive"}
            if not comment:
                # Allow empty comment to clear existing comment
                comment = ""

            # Get function address
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {
                    "success": False,
                    "message": f"Function '{function_name}' not found",
                }

            # Check if it's a function
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {
                    "success": False,
                    "message": f"'{function_name}' is not a function",
                }

            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {
                    "success": False,
                    "message": "Hex-Rays decompiler is not available",
                }

            # Get decompilation result
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {
                    "success": False,
                    "message": f"Failed to decompile function '{function_name}'",
                }

            # Get pseudocode
            pseudocode = cfunc.get_pseudocode()
            if not pseudocode or pseudocode.size() == 0:
                return {"success": False, "message": "No pseudocode generated"}

            # Check if line number is valid
            if line_number > pseudocode.size():
                return {
                    "success": False,
                    "message": f"Line number {line_number} is out of range (max is {pseudocode.size()})",
                }

            # Line numbers in the API are 0-based, but user input is 1-based
            actual_line_index = line_number - 1

            # Get the ctree item for the specified line
            line_item = pseudocode[actual_line_index]
            tree_item = cfunc.treeitems[actual_line_index]
            print(tree_item, tree_item.ea)
            if not line_item:
                return {
                    "success": False,
                    "message": f"Cannot access line {line_number}",
                }

            # Create a treeloc_t object for the comment location
            loc = ida_hexrays.treeloc_t()
            loc.ea = tree_item.ea
            loc.itp = ida_hexrays.ITP_SEMI  # Comment position (can adjust as needed)

            for tree_item in cfunc.treeitems:
                print(tree_item.index)

            cfunc.set_user_cmt(loc, comment)
            cfunc.save_user_cmts()

            self._view_refresh_impl()

            comment_type = "repeatable" if is_repeatable else "regular"
            return {
                "success": True,
                "message": f"Added {comment_type} comment to line {line_number} at address {hex(line_ea)}",
            }

        except Exception as e:
            print(f"Error adding pseudocode line comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    def view_refresh(self, data):
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(lambda: wrapper(self._view_refresh_impl), idaapi.MFF_WRITE)
        return wrapper.result

    def _view_refresh_impl(self):
        try:
            idaapi.refresh_idaview_anyway()

            current_widget = idaapi.get_current_widget()
            if current_widget:
                widget_type = idaapi.get_widget_type(current_widget)
                if widget_type == idaapi.BWN_PSEUDOCODE:
                    vu = idaapi.get_widget_vdui(current_widget)
                    if vu:
                        vu.view_refresh(True)

            # iterate over all pseudocode views (Pseudocode-A, Pseudocode-B, ...)
            for i in range(5):
                widget_name = f"Pseudocode-{chr(65+i)}"
                widget = idaapi.find_widget(widget_name)
                if widget:
                    vu = idaapi.get_widget_vdui(widget)
                    if vu:
                        vu.view_refresh(True)

            return {"success": True, "message": "Views refreshed successfully"}
        except Exception as e:
            print(f"Error refreshing views: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}


class IDAMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "IDA MCP Server Plugin"
    help = "Provides MCP server functionality for IDAPro"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def __init__(self):
        super(IDAMCPPlugin, self).__init__()
        self.server = None
        self.initialized = False
        self.menu_items_added = False
        print(f"IDAMCPPlugin instance created")

    def init(self):
        try:
            print(f"{PLUGIN_NAME} v{PLUGIN_VERSION} by {PLUGIN_AUTHOR}")
            print("Initializing plugin...")

            if not self.menu_items_added:
                self.create_menu_items()
                self.menu_items_added = True
                print("Menu items added")

            self.initialized = True
            print("Plugin initialized successfully")

            idaapi.register_timer(500, self._delayed_server_start)

            return idaapi.PLUGIN_KEEP
        except Exception as e:
            print(f"Error initializing plugin: {str(e)}")
            traceback.print_exc()
            return idaapi.PLUGIN_SKIP

    def _delayed_server_start(self):
        # delayed server start to avoid initialization race conditions
        try:
            if not self.server or not self.server.running:
                print("Delayed server start...")
                self.start_server()
        except Exception as e:
            print(f"Error in delayed server start: {str(e)}")
            traceback.print_exc()
        return -1

    def create_menu_items(self):
        menu_path = "Edit/Plugins/"

        class StartServerHandler(idaapi.action_handler_t):
            def __init__(self, plugin):
                idaapi.action_handler_t.__init__(self)
                self.plugin = plugin

            def activate(self, ctx):
                self.plugin.start_server()
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        class StopServerHandler(idaapi.action_handler_t):
            def __init__(self, plugin):
                idaapi.action_handler_t.__init__(self)
                self.plugin = plugin

            def activate(self, ctx):
                self.plugin.stop_server()
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        try:
            start_action_name = "mcp:start_server"
            start_action_desc = idaapi.action_desc_t(
                start_action_name,
                "Start MCP Server",
                StartServerHandler(self),
                "Ctrl+Alt+S",
                "Start the MCP Server",
                199,
            )

            stop_action_name = "mcp:stop_server"
            stop_action_desc = idaapi.action_desc_t(
                stop_action_name,
                "Stop MCP Server",
                StopServerHandler(self),
                "Ctrl+Alt+X",
                "Stop the MCP Server",
                200,
            )

            if not idaapi.register_action(start_action_desc):
                print("Failed to register start server action")
            if not idaapi.register_action(stop_action_desc):
                print("Failed to register stop server action")

            if not idaapi.attach_action_to_menu(
                menu_path + "Start MCP Server", start_action_name, idaapi.SETMENU_APP
            ):
                print("Failed to attach start server action to menu")
            if not idaapi.attach_action_to_menu(
                menu_path + "Stop MCP Server", stop_action_name, idaapi.SETMENU_APP
            ):
                print("Failed to attach stop server action to menu")

            print("Menu items created successfully")
        except Exception as e:
            print(f"Error creating menu items: {str(e)}")
            traceback.print_exc()

    def start_server(self):
        if self.server and self.server.running:
            print("MCP Server is already running")
            return

        try:
            print("Creating MCP Server instance...")
            self.server = IDAMCPServer()
            print("Starting MCP Server...")
            if self.server.start():
                print("MCP Server started successfully")
            else:
                print("Failed to start MCP Server")
        except Exception as e:
            print(f"Error starting server: {str(e)}")
            traceback.print_exc()

    def stop_server(self):
        if not self.server:
            print("MCP Server instance does not exist")
            return

        if not self.server.running:
            print("MCP Server is not running")
            return

        try:
            self.server.stop()
            print("MCP Server stopped by user")
        except Exception as e:
            print(f"Error stopping server: {str(e)}")
            traceback.print_exc()

    def run(self, arg):
        if not self.initialized:
            print("Plugin not initialized")
            return

        try:
            if not self.server or not self.server.running:
                print("Hotkey triggered: starting server")
                self.start_server()
            else:
                print("Hotkey triggered: stopping server")
                self.stop_server()
        except Exception as e:
            print(f"Error in run method: {str(e)}")
            traceback.print_exc()

    def term(self):
        try:
            if self.server and self.server.running:
                print("Terminating plugin: stopping server")
                self.server.stop()
            print(f"{PLUGIN_NAME} terminated")
        except Exception as e:
            print(f"Error terminating plugin: {str(e)}")
            traceback.print_exc()


def PLUGIN_ENTRY():
    return IDAMCPPlugin()
