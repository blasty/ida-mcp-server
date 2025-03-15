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
import uuid

PLUGIN_NAME = "IDA MCP Server"
PLUGIN_HOTKEY = "Ctrl-Alt-M"
PLUGIN_VERSION = "1.0"
PLUGIN_AUTHOR = "IDA MCP"

# 默认配置
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000

class IDASyncWrapper(object):
    """包装器类，用于从execute_sync获取返回值"""
    def __init__(self):
        self.result = None

    def __call__(self, func, *args, **kwargs):
        self.result = func(*args, **kwargs)
        return 1

class IDACommunicator:
    """IDA 通信类"""
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
        """启动Socket服务器"""
        if self.running:
            print("MCP Server already running")
            return False
            
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # 设置超时，使服务器可以响应停止请求
            
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
        """停止Socket服务器"""
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
                self.thread.join(2.0)  # 等待线程结束，最多2秒
            except Exception as e:
                print(f"Error joining server thread: {str(e)}")
            self.thread = None
            
        print("MCP Server stopped")
    
    def send_message(self, client_socket, data: bytes) -> None:
        """发送带长度前缀的消息"""
        length = len(data)
        length_bytes = struct.pack('!I', length)  # 4字节的长度前缀
        client_socket.sendall(length_bytes + data)

    def receive_message(self, client_socket) -> bytes:
        """接收带长度前缀的消息"""
        # 接收4字节的长度前缀
        length_bytes = self.receive_exactly(client_socket, 4)
        if not length_bytes:
            raise ConnectionError("连接已关闭")
            
        length = struct.unpack('!I', length_bytes)[0]
        
        # 接收消息主体
        data = self.receive_exactly(client_socket, length)
        return data

    def receive_exactly(self, client_socket, n: int) -> bytes:
        """接收确切的n字节数据"""
        data = b''
        while len(data) < n:
            chunk = client_socket.recv(min(n - len(data), 4096))
            if not chunk:  # 连接已关闭
                raise ConnectionError("连接关闭，无法接收完整数据")
            data += chunk
        return data
    
    def server_loop(self):
        """服务器主循环"""
        print("Server loop started")
        while self.running:
            try:
                # 使用超时接收，这样可以周期性检查running标志
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.client_counter += 1
                    client_id = self.client_counter
                    print(f"Client #{client_id} connected from {client_address}")
                    
                    # 处理客户端请求 - 使用线程以支持多个客户端
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    # 超时只是为了周期性检查running标志
                    continue
                except OSError as e:
                    if self.running:  # 只在服务器运行时打印错误
                        if e.errno == 9:  # Bad file descriptor，通常是socket已关闭
                            print("Server socket was closed")
                            break
                        print(f"Socket error: {str(e)}")
                except Exception as e:
                    if self.running:  # 只在服务器运行时打印错误
                        print(f"Error accepting connection: {str(e)}")
                        traceback.print_exc()
            except Exception as e:
                if self.running:
                    print(f"Error in server loop: {str(e)}")
                    traceback.print_exc()
                time.sleep(1)  # 避免CPU占用过高
        
        print("Server loop ended")
    
    def handle_client(self, client_socket, client_id):
        """处理客户端请求"""
        try:
            # 设置超时
            client_socket.settimeout(30)
            
            while self.running:
                try:
                    # 接收消息
                    data = self.receive_message(client_socket)
                    
                    # 解析请求
                    request = json.loads(data.decode('utf-8'))
                    request_type = request.get('type')
                    request_data = request.get('data', {})
                    request_id = request.get('id', 'unknown')
                    request_count = request.get('count', -1)
                    
                    print(f"Client #{client_id} request: {request_type}, ID: {request_id}, Count: {request_count}")
                    
                    # 处理不同类型的请求
                    response = {
                        "id": request_id,  # 返回相同的请求ID
                        "count": request_count  # 返回相同的请求计数
                    }
                    
                    if request_type == "get_function_assembly":
                        result = self.get_function_assembly(request_data)
                        response.update(result)
                    elif request_type == "get_function_decompiled":
                        result = self.get_function_decompiled(request_data)
                        response.update(result)
                    elif request_type == "get_global_variable":
                        result = self.get_global_variable(request_data)
                        response.update(result)
                    elif request_type == "get_current_function_assembly":
                        result = self.get_current_function_assembly()
                        response.update(result)
                    elif request_type == "get_current_function_decompiled":
                        result = self.get_current_function_decompiled()
                        response.update(result)
                    elif request_type == "ping":
                        response["status"] = "pong"
                    else:
                        response["error"] = f"Unknown request type: {request_type}"
                    
                    # 验证响应是否正确
                    if not isinstance(response, dict):
                        print(f"Response is not a dictionary: {type(response).__name__}")
                        response = {
                            "id": request_id,
                            "count": request_count,
                            "error": f"Internal server error: response is not a dictionary but {type(response).__name__}"
                        }
                    
                    # 确保响应中的所有值都是可序列化的
                    for key, value in list(response.items()):
                        if value is None:
                            response[key] = "null"
                        elif not isinstance(value, (str, int, float, bool, list, dict, tuple)):
                            print(f"Response key '{key}' has non-serializable type: {type(value).__name__}")
                            response[key] = str(value)
                        
                    # 发送响应
                    response_json = json.dumps(response).encode('utf-8')
                    self.send_message(client_socket, response_json)
                    print(f"Sent response to client #{client_id}, ID: {request_id}, Count: {request_count}")
                    
                except ConnectionError as e:
                    print(f"Connection with client #{client_id} lost: {str(e)}")
                    return
                except socket.timeout:
                    print(f"Socket timeout with client #{client_id}")
                    continue
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON request from client #{client_id}: {str(e)}")
                    try:
                        response = {
                            "error": f"Invalid JSON request: {str(e)}"
                        }
                        self.send_message(client_socket, json.dumps(response).encode('utf-8'))
                    except:
                        print(f"Failed to send error response to client #{client_id}")
                except Exception as e:
                    print(f"Error processing request from client #{client_id}: {str(e)}")
                    traceback.print_exc()
                    try:
                        response = {
                            "error": str(e)
                        }
                        self.send_message(client_socket, json.dumps(response).encode('utf-8'))
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
    
    # 核心功能实现
    def get_function_assembly(self, data):
        """获取函数的汇编代码"""
        function_name = data.get("function_name", "")
        
        # 使用SyncWrapper来获取结果
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(lambda: wrapper(self._get_function_assembly_impl, function_name), idaapi.MFF_READ)
        return wrapper.result
    
    def _get_function_assembly_impl(self, function_name):
        """在IDA主线程中实现获取函数汇编的逻辑"""
        try:
            # 获取函数地址
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}
            
            # 获取函数对象
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"error": f"Invalid function at {hex(func_addr)}"}
            
            # 收集函数的所有汇编指令
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
    
    def get_function_decompiled(self, data):
        """获取函数的反编译伪代码"""
        function_name = data.get("function_name", "")
        
        # 使用SyncWrapper来获取结果
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(lambda: wrapper(self._get_function_decompiled_impl, function_name), idaapi.MFF_READ)
        return wrapper.result
    
    def _get_function_decompiled_impl(self, function_name):
        """在IDA主线程中实现获取函数反编译代码的逻辑"""
        try:
            # 获取函数地址
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}
            
            # 获取函数对象
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"error": f"Invalid function at {hex(func_addr)}"}
            
            # 检查反编译器是否可用
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Hex-Rays decompiler not available"}
            
            # 获取反编译结果
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"error": "Failed to decompile function"}
            
            # 获取伪代码文本
            sv = cfunc.get_pseudocode()
            if not sv:
                return {"error": "No pseudocode generated"}
                
            decompiled_text = []
            
            for sline in sv:
                line_text = ida_lines.tag_remove(sline.line)
                if line_text is not None:  # 确保不是None
                    decompiled_text.append(line_text)
            
            # 确保始终返回字符串
            if not decompiled_text:
                return {"decompiled_code": "// No code content available"}
                
            result = "\n".join(decompiled_text)
            
            # 调试输出
            print(f"Decompiled text type: {type(result).__name__}, length: {len(result)}")
            
            return {"decompiled_code": result}
        except Exception as e:
            print(f"Error decompiling function: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    def get_global_variable(self, data):
        """获取全局变量信息"""
        variable_name = data.get("variable_name", "")
        
        # 使用SyncWrapper来获取结果
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(lambda: wrapper(self._get_global_variable_impl, variable_name), idaapi.MFF_READ)
        return wrapper.result
    
    def _get_global_variable_impl(self, variable_name):
        """在IDA主线程中实现获取全局变量的逻辑"""
        try:
            # 获取变量地址
            var_addr = ida_name.get_name_ea(0, variable_name)
            if var_addr == idaapi.BADADDR:
                return {"error": f"Global variable '{variable_name}' not found"}
            
            # 获取变量所在的段
            segment = ida_segment.getseg(var_addr)
            if not segment:
                return {"error": f"No segment found for address {hex(var_addr)}"}
            
            segment_name = ida_segment.get_segm_name(segment)
            segment_class = ida_segment.get_segm_class(segment)
            
            # 获取变量类型
            tinfo = idaapi.tinfo_t()
            guess_type = idaapi.guess_tinfo(var_addr, tinfo)
            type_str = tinfo.get_type_name() if guess_type else "unknown"
            
            # 尝试获取变量值
            size = ida_bytes.get_item_size(var_addr)
            if size <= 0:
                size = 8  # 默认尝试读取8字节
            
            # 根据大小读取数据
            value = None
            if size == 1:
                value = ida_bytes.get_byte(var_addr)
            elif size == 2:
                value = ida_bytes.get_word(var_addr)
            elif size == 4:
                value = ida_bytes.get_dword(var_addr)
            elif size == 8:
                value = ida_bytes.get_qword(var_addr)
            
            # 构建变量信息
            var_info = {
                "name": variable_name,
                "address": hex(var_addr),
                "segment": segment_name,
                "segment_class": segment_class,
                "type": type_str,
                "size": size,
                "value": hex(value) if value is not None else "N/A"
            }
            
            # 如果是字符串，尝试读取字符串内容
            if ida_bytes.is_strlit(ida_bytes.get_flags(var_addr)):
                str_value = idc.get_strlit_contents(var_addr, -1, 0)
                if str_value:
                    try:
                        var_info["string_value"] = str_value.decode('utf-8', errors='replace')
                    except:
                        var_info["string_value"] = str(str_value)
            
            return {"variable_info": json.dumps(var_info, indent=2)}
        except Exception as e:
            print(f"Error getting global variable: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
            
    # 新增功能：获取当前函数的汇编代码
    def get_current_function_assembly(self):
        """获取当前光标所在函数的汇编代码"""
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(lambda: wrapper(self._get_current_function_assembly_impl), idaapi.MFF_READ)
        return wrapper.result
    
    def _get_current_function_assembly_impl(self):
        """在IDA主线程中实现获取当前函数汇编的逻辑"""
        try:
            # 获取当前光标所在地址
            current_addr = idaapi.get_screen_ea()
            if current_addr == idaapi.BADADDR:
                return {"error": "Invalid cursor position"}
            
            # 获取函数对象
            func = ida_funcs.get_func(current_addr)
            if not func:
                return {"error": f"No function found at current position {hex(current_addr)}"}
            
            # 获取函数名称
            func_name = ida_funcs.get_func_name(func.start_ea)
            
            # 收集函数的所有汇编指令
            assembly_lines = []
            for instr_addr in idautils.FuncItems(func.start_ea):
                disasm = idc.GetDisasm(instr_addr)
                assembly_lines.append(f"{hex(instr_addr)}: {disasm}")
            
            if not assembly_lines:
                return {"error": "No assembly instructions found"}
                
            return {
                "function_name": func_name,
                "function_address": hex(func.start_ea),
                "assembly": "\n".join(assembly_lines)
            }
        except Exception as e:
            print(f"Error getting current function assembly: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    # 新增功能：获取当前函数的反编译代码
    def get_current_function_decompiled(self):
        """获取当前光标所在函数的反编译代码"""
        wrapper = IDASyncWrapper()
        idaapi.execute_sync(lambda: wrapper(self._get_current_function_decompiled_impl), idaapi.MFF_READ)
        return wrapper.result
    
    def _get_current_function_decompiled_impl(self):
        """在IDA主线程中实现获取当前函数反编译代码的逻辑"""
        try:
            # 获取当前光标所在地址
            current_addr = idaapi.get_screen_ea()
            if current_addr == idaapi.BADADDR:
                return {"error": "Invalid cursor position"}
            
            # 获取函数对象
            func = ida_funcs.get_func(current_addr)
            if not func:
                return {"error": f"No function found at current position {hex(current_addr)}"}
            
            # 获取函数名称
            func_name = ida_funcs.get_func_name(func.start_ea)
            
            # 检查反编译器是否可用
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Hex-Rays decompiler not available"}
            
            # 获取反编译结果
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"error": "Failed to decompile function"}
            
            # 获取伪代码文本
            sv = cfunc.get_pseudocode()
            if not sv:
                return {"error": "No pseudocode generated"}
                
            decompiled_text = []
            
            for sline in sv:
                line_text = ida_lines.tag_remove(sline.line)
                if line_text is not None:  # 确保不是None
                    decompiled_text.append(line_text)
            
            # 确保始终返回字符串
            if not decompiled_text:
                return {"decompiled_code": "// No code content available"}
                
            result = "\n".join(decompiled_text)
            
            # 调试输出
            print(f"Current function decompiled text type: {type(result).__name__}, length: {len(result)}")
            
            return {
                "function_name": func_name,
                "function_address": hex(func.start_ea),
                "decompiled_code": result
            }
        except Exception as e:
            print(f"Error decompiling current function: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}

# IDA插件类
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
    
    # ... 其余代码与之前相同，只需将IdaMcp更改为IDAMCP ...
    def init(self):
        """插件初始化"""
        try:
            print(f"{PLUGIN_NAME} v{PLUGIN_VERSION} by {PLUGIN_AUTHOR}")
            print("Initializing plugin...")
            
            # 添加菜单项
            if not self.menu_items_added:
                self.create_menu_items()
                self.menu_items_added = True
                print("Menu items added")
            
            # 标记为已初始化
            self.initialized = True
            print("Plugin initialized successfully")
            
            # 延迟启动服务器，避免初始化问题
            idaapi.register_timer(500, self._delayed_server_start)
            
            return idaapi.PLUGIN_KEEP
        except Exception as e:
            print(f"Error initializing plugin: {str(e)}")
            traceback.print_exc()
            return idaapi.PLUGIN_SKIP
    
    def _delayed_server_start(self):
        """延迟启动服务器，避免初始化竞争条件"""
        try:
            if not self.server or not self.server.running:
                print("Delayed server start...")
                self.start_server()
        except Exception as e:
            print(f"Error in delayed server start: {str(e)}")
            traceback.print_exc()
        return -1  # 不重复执行
    
    def create_menu_items(self):
        """创建插件菜单项"""
        # 创建菜单项
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
            # 注册并添加开始服务器的动作
            start_action_name = "mcp:start_server"
            start_action_desc = idaapi.action_desc_t(
                start_action_name,
                "Start MCP Server",
                StartServerHandler(self),
                "Ctrl+Alt+S",
                "Start the MCP Server",
                199  # 图标ID
            )
            
            # 注册并添加停止服务器的动作
            stop_action_name = "mcp:stop_server"
            stop_action_desc = idaapi.action_desc_t(
                stop_action_name, 
                "Stop MCP Server",
                StopServerHandler(self),
                "Ctrl+Alt+X",
                "Stop the MCP Server",
                200  # 图标ID
            )
            
            # 注册动作
            if not idaapi.register_action(start_action_desc):
                print("Failed to register start server action")
            if not idaapi.register_action(stop_action_desc):
                print("Failed to register stop server action")
            
            # 添加到菜单
            if not idaapi.attach_action_to_menu(menu_path + "Start MCP Server", start_action_name, idaapi.SETMENU_APP):
                print("Failed to attach start server action to menu")
            if not idaapi.attach_action_to_menu(menu_path + "Stop MCP Server", stop_action_name, idaapi.SETMENU_APP):
                print("Failed to attach stop server action to menu")
                
            print("Menu items created successfully")
        except Exception as e:
            print(f"Error creating menu items: {str(e)}")
            traceback.print_exc()
    
    def start_server(self):
        """启动服务器"""
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
        """停止服务器"""
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
        """按下热键时执行"""
        if not self.initialized:
            print("Plugin not initialized")
            return
        
        # 热键触发时自动启动或停止服务器
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
        """插件终止"""
        try:
            if self.server and self.server.running:
                print("Terminating plugin: stopping server")
                self.server.stop()
            print(f"{PLUGIN_NAME} terminated")
        except Exception as e:
            print(f"Error terminating plugin: {str(e)}")
            traceback.print_exc()



# 注册插件
def PLUGIN_ENTRY():
    return IDAMCPPlugin()
