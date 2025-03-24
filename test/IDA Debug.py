# import idapro
import traceback
import idaapi
import idautils
import idc
import ida_funcs

# class FunctionDump(object):
#     def __init__(self):
#         self.c_functions = []
#         self.c_functions_lookup = {}
        
#     def parse(self):
#         for func_ea in idautils.Functions():
#             if self.is_user_defined_c_function(func_ea):
#                 function_name = ida_funcs.get_func_name(func_ea)
#                 self.c_functions.append(function_name)
#                 self.c_functions_lookup[function_name] = func_ea
                
#     def is_user_defined_c_function(self, ea):
#         flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)

#         # Check if it's a library function
#         if flags & idaapi.FUNC_LIB:
#             return False

#         # Check if it's a thunk function
#         if flags & idaapi.FUNC_THUNK:
#             return False

#         func_name = idc.get_func_name(ea)

#         # Exclude Objective-C methods (usually start with +/- or contain ::)
#         if func_name.startswith(('+', '-')) or '::' in func_name:
#             return False

#         # Exclude common system function prefixes
#         system_prefixes = ['block_invoke', 'helper_block', 'Block_byref']
#         if any(func_name.__contains__(prefix) for prefix in system_prefixes):
#             return False

#         return True



# dump = FunctionDump()
# dump.parse()

# print(f"Found {len(dump.c_functions)} user-defined C functions:")
# for func_name in dump.c_functions:
#     print(f"Function: {func_name}")
    
import idaapi
import ida_name
import ida_hexrays
import ida_funcs
import idautils

# idapro.open_database("/Volumes/FrameworkLab/Dyld-Shared-Cache/macOS/15.1/dyld_shared_cache_arm64e-LaunchServices.i64", True)  # 替换为你的数据库路径

# print(ida_name.demangle_name("__UXCollectionView_indexPathsForItemsInSections_includingOverdrawArea__", idc.get_inf_attr(idc.INF_LONG_DN)))
# print(idc.demangle_name("__UXCollectionView__indexPathsForItemsInSections_includingOverdrawArea__", idc.get_inf_attr(idc.INF_LONG_DN)))
# for function in idautils.Functions():
#     function_name = ida_funcs.get_func_name(function)
#     print(function_name)

def _rename_local_variable_impl(function_name, old_name, new_name):
        """在IDA主线程中实现重命名函数内局部变量的逻辑"""
        try:
            # 参数验证
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not old_name:
                return {"success": False, "message": "Old variable name cannot be empty"}
            if not new_name:
                return {"success": False, "message": "New variable name cannot be empty"}
            
            # 获取函数地址
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # 检查是否是函数
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # 检查反编译器是否可用
            if not ida_hexrays.init_hexrays_plugin():
                return {"success": False, "message": "Hex-Rays decompiler is not available"}
            
            # 获取反编译结果
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
            
            # 找到要重命名的局部变量
            found = False
            renamed = False
            lvar = None
            
            # 遍历所有局部变量
            lvars = cfunc.get_lvars()
            print(lvars)
            for i in range(lvars.size()):
                v = lvars[i]
                print(v)
                if v.name == old_name:
                    print(v.name)
                    lvar = v
                    found = True
                    break
            
            if not found:
                return {"success": False, "message": f"Local variable '{old_name}' not found in function '{function_name}'"}
            
            # 重命名局部变量
            if ida_hexrays.rename_lvar(cfunc.entry_ea, lvar.name, new_name):
                renamed = True
            
            if renamed:
                return {"success": True, "message": f"Local variable renamed from '{old_name}' to '{new_name}' in function '{function_name}'"}
            else:
                return {"success": False, "message": f"Failed to rename local variable from '{old_name}' to '{new_name}', possibly due to invalid name format or other IDA restrictions"}
        
        except Exception as e:
            print(f"Error renaming local variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
        

def _add_pseudocode_line_comment_impl(function_name, line_number, comment, is_repeatable):
    """Implement adding a comment to a specific line of pseudocode in the IDA main thread"""
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
            return {"success": False, "message": f"Function '{function_name}' not found"}
        
        # Check if it's a function
        func = ida_funcs.get_func(func_addr)
        if not func:
            return {"success": False, "message": f"'{function_name}' is not a function"}
        
        # Check if decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return {"success": False, "message": "Hex-Rays decompiler is not available"}
        
        # Get decompilation result
        cfunc = ida_hexrays.decompile(func_addr)
        if not cfunc:
            return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
        
        # Get pseudocode
        pseudocode = cfunc.get_pseudocode()
        if not pseudocode or pseudocode.size() == 0:
            return {"success": False, "message": "No pseudocode generated"}

        # Check if line number is valid
        if line_number > pseudocode.size():
            return {"success": False, "message": f"Line number {line_number} is out of range (max is {pseudocode.size()})"}
        
        # Line numbers in the API are 0-based, but user input is 1-based
        actual_line_index = line_number - 1
        
        # Get the ctree item for the specified line
        line_item = pseudocode[actual_line_index]
        tree_item = cfunc.treeitems[actual_line_index]
        # print(cfunc.treeitems.count())
        print(tree_item, tree_item.ea)
        if not line_item:
            return {"success": False, "message": f"Cannot access line {line_number}"}
        
        # Create a treeloc_t object for the comment location
        loc = ida_hexrays.treeloc_t()
        loc.ea = tree_item.ea
        loc.itp = ida_hexrays.ITP_SEMI  # Comment position (can adjust as needed)

        for tree_item in cfunc.treeitems:
            print(tree_item.index)
        
        # Set the comment
        cfunc.set_user_cmt(loc, comment)
        cfunc.save_user_cmts()
        # if result:
        #     # Refresh decompiler view to show the comment
        try:
            # 刷新反汇编视图
            idaapi.refresh_idaview_anyway()
            
            # 刷新反编译视图
            current_widget = idaapi.get_current_widget()
            if current_widget:
                widget_type = idaapi.get_widget_type(current_widget)
                if widget_type == idaapi.BWN_PSEUDOCODE:
                    # 如果当前是伪代码视图，刷新它
                    vu = idaapi.get_widget_vdui(current_widget)
                    if vu:
                        vu.refresh_view(True)
            
            # 尝试查找并刷新所有打开的伪代码窗口
            for i in range(5):  # 检查多个可能的伪代码窗口
                widget_name = f"Pseudocode-{chr(65+i)}"  # Pseudocode-A, Pseudocode-B, ...
                widget = idaapi.find_widget(widget_name)
                if widget:
                    vu = idaapi.get_widget_vdui(widget)
                    if vu:
                        vu.refresh_view(True)
            
            return {"success": True, "message": "Views refreshed successfully"}
        except Exception as e:
            print(f"Error refreshing views: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
        #     return {
        #         "success": True, 
        #         "message": f"Added comment to line {line_number} in pseudocode"
        #     }
        # else:
        #     # Try alternative method
        #     cmts = cfunc.get_user_cmts()
        #     if not cmts:
        #         return {"success": False, "message": "Failed to add comment - could not get user comments"}
            
        #     # Try to find the appropriate tree item for this line
        #     for item in cfunc.treeitems:
        #         if item and item.ea != idaapi.BADADDR and item.line_num == actual_line_index:
        #             # Create a comment using the item's index
        #             cmts[item.index] = ida_hexrays.citem_cmt_t(comment)
        #             ida_hexrays.refresh_idaview_anyway()
        #             return {
        #                 "success": True,
        #                 "message": f"Added comment to line {line_number} using alternative method"
        #             }
            
        return {
            "success": True, 
            "message": f"Added comment to line {line_number} using alternative method"
        }
    
    except Exception as e:
        print(f"Error adding pseudocode line comment: {str(e)}")
        traceback.print_exc()
        return {"success": False, "message": str(e)}
        
print(_add_pseudocode_line_comment_impl("+[_LSDService XPCConnectionToService]", 1, "TestC", True))
# idapro.close_database()