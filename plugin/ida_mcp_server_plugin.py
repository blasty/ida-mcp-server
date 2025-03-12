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
import threading
import traceback

PLUGIN_NAME = "IDA MCP Server"
PLUGIN_HOTKEY = "Ctrl-Alt-M"
PLUGIN_VERSION = "1.0"
PLUGIN_AUTHOR = "IDA MCP"

# 默认配置
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000

class IdaMcpServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None
    
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
            return
            
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        
        if self.thread:
            self.thread.join(2.0)  # 等待线程结束
            self.thread = None
            
        print("MCP Server stopped")
    
    def server_loop(self):
        """服务器主循环"""
        print("Server loop started")
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"Client connected: {client_address}")
                
                # 处理客户端请求
                self.handle_client(client_socket)
            except Exception as e:
                if self.running:  # 只在服务器运行时打印错误
                    print(f"Error accepting connection: {str(e)}")
                    traceback.print_exc()
    
    def handle_client(self, client_socket):
        """处理客户端请求"""
        try:
            # 接收请求数据
            data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(chunk) < 4096:  # 简单判断接收完成
                    break
            
            if not data:
                return
                
            # 解析请求
            request = json.loads(data.decode('utf-8'))
            request_type = request.get('type')
            request_data = request.get('data', {})
            
            # 处理不同类型的请求
            response = {}
            if request_type == "get_function_assembly":
                response = self.get_function_assembly(request_data)
            elif request_type == "get_function_decompiled":
                response = self.get_function_decompiled(request_data)
            elif request_type == "get_global_variable":
                response = self.get_global_variable(request_data)
            else:
                response = {"error": f"Unknown request type: {request_type}"}
            
            # 发送响应
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            print(f"Error handling client request: {str(e)}")
            traceback.print_exc()
            try:
                client_socket.sendall(json.dumps({"error": str(e)}).encode('utf-8'))
            except:
                pass
        finally:
            client_socket.close()
    
    def get_function_assembly(self, data):
        """获取函数的汇编代码"""
        function_name = data.get("function_name", "")
        
        # 在IDA主线程中执行API调用
        result = idaapi.execute_sync(lambda: self._get_function_assembly_impl(function_name), idaapi.MFF_READ)
        return result
    
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
        
        # 在IDA主线程中执行API调用
        result = idaapi.execute_sync(lambda: self._get_function_decompiled_impl(function_name), idaapi.MFF_READ)
        return result
    
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
            decompiled_text = []
            
            for sline in sv:
                decompiled_text.append(ida_lines.tag_remove(sline.line))
            
            return {"decompiled_code": "\n".join(decompiled_text)}
        except Exception as e:
            print(f"Error decompiling function: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    def get_global_variable(self, data):
        """获取全局变量信息"""
        variable_name = data.get("variable_name", "")
        
        # 在IDA主线程中执行API调用
        result = idaapi.execute_sync(lambda: self._get_global_variable_impl(variable_name), idaapi.MFF_READ)
        return result
    
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


# IDA插件类
class IdaMcpPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "IDA MCP Server Plugin"
    help = "Provides MCP server functionality for IDAPro"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    
    def __init__(self):
        self.server = None
        self.initialized = False
    
    def init(self):
        """插件初始化"""
        try:
            print(f"{PLUGIN_NAME} v{PLUGIN_VERSION} by {PLUGIN_AUTHOR}")
            
            # 添加菜单项
            self.create_menu_items()
            
            self.initialized = True
            return idaapi.PLUGIN_KEEP
        except Exception as e:
            print(f"Error initializing plugin: {str(e)}")
            traceback.print_exc()
            return idaapi.PLUGIN_SKIP
    
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
        idaapi.register_action(start_action_desc)
        idaapi.register_action(stop_action_desc)
        
        # 添加到菜单
        idaapi.attach_action_to_menu(menu_path + "Start MCP Server", start_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(menu_path + "Stop MCP Server", stop_action_name, idaapi.SETMENU_APP)
    
    def start_server(self):
        """启动服务器"""
        if self.server and self.server.running:
            print("MCP Server is already running")
            return
        
        self.server = IdaMcpServer()
        if self.server.start():
            print("MCP Server started successfully")
        else:
            print("Failed to start MCP Server")
    
    def stop_server(self):
        """停止服务器"""
        if self.server and self.server.running:
            self.server.stop()
            print("MCP Server stopped")
        else:
            print("MCP Server is not running")
    
    def run(self, arg):
        """按下热键时执行"""
        if not self.initialized:
            print("Plugin not initialized")
            return
        
        # 热键触发时自动启动服务器
        if not self.server or not self.server.running:
            self.start_server()
        else:
            self.stop_server()
    
    def term(self):
        """插件终止"""
        if self.server and self.server.running:
            self.server.stop()
        print(f"{PLUGIN_NAME} terminated")


# 注册插件
def PLUGIN_ENTRY():
    return IdaMcpPlugin()
