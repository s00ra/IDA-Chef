'''
 ___   ______   _______    _______  __   __  _______  _______ 
|   | |      | |   _   |  |       ||  | |  ||       ||       |
|   | |  _    ||  |_|  |  |       ||  |_|  ||    ___||    ___|
|   | | | |   ||       |  |       ||       ||   |___ |   |___ 
|   | | |_|   ||       |  |      _||       ||    ___||    ___|
|   | |       ||   _   |  |     |_ |   _   ||   |___ |   |    
|___| |______| |__| |__|  |_______||__| |__||_______||___|    
'''

# Discord: 50r4#8751
# linked-in: https://www.linkedin.com/in/ahmed-raof-97b6921a9/

__AUTHOR__ = '@50r4' # Ahmed Raof

PLUGIN_NAME = "IDA Chef"
PLUGIN_HOTKEY = 'Ctrl+Shift+A'
VERSION = '1.0.0'

import os
import sys
import typing
import idc
import idaapi
import idautils
import ida_kernwin

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QMessageBox, QVBoxLayout, QMenu, QWidget
from PyQt5.QtGui import QCursor, QKeySequence

# import all crypto functions
    # Note that you can add your own <file.py> into "fun_crypto folder"
                                    # OR 
    # you can write your function into interactive python and add -> it will be added into <c.py> automatically or into a new file
# from fun_crypto import *

ACTION_MENU  = ["idaChef:menu%d" % i for i in range(2)]
set_as_var = {}

#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------
class Hooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        # A right click menu is about to be shown. (IDA 7)
        inject_hex_decrypt_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        # A right click menu is about to be shown. (IDA 6.x)
        inject_hex_decrypt_actions(form, popup, idaapi.get_tform_type(form))
        return 0

#------------------------------------------------------------------------------
# Prefix Wrappers
#------------------------------------------------------------------------------
def inject_hex_decrypt_actions(form, popup, form_type):
    # Inject prefix actions to popup menu(s) based on context.

    # disassembly window
    if form_type == idaapi.BWN_DISASMS:

        # insert the prefix action entry into the menu
        for action in ACTION_MENU:
            idaapi.attach_action_to_popup(form, popup, action, "IDA Chef/")
            
    return 0

#------------------------------------------------------------------------------
# IDA ctxt
#------------------------------------------------------------------------------
class menu_action_handler_t(idaapi.action_handler_t):
    # A basic Context Menu class to utilize IDA's action handlers.
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        # Execute the embedded action_function when this context menu is invoked.
        if self.action_function in ACTION_MENU:
            if self.action_function == ACTION_MENU[0]:
                win = ida_chef_window()
                win.Show()
            elif self.action_function == ACTION_MENU[1]:
                v = ida_chef_set_var()
                v, args = v.Compile()
                ok = v.Execute()
                if ok == 1:
                    set_as_var[v.var_name.value] = v.copy_bytes()
                    print(set_as_var)
                v.Free()
        return 1

    def update(self, ctx):
        # Ensure the context menu is always available in IDA.
        return idaapi.AST_ENABLE_ALWAYS

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class ida_chef(idaapi.plugin_t):
    # IDAChef
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Decrypt anything you want"
    help = "Curiosity keeps leading us down new paths"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    #--------------------------------------------------------------------------
    # Plugin Overloads
    #--------------------------------------------------------------------------

    # This is called by IDA when it is loading the plugin.
    def init(self):
        self.registered_actions = []
        # initialize the menu actions our plugin will inject
        self._init_action_decrypt_bytes()
        # initialize plugin hooks
        self._init_hooks()
        # done
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    # This is called by IDA when this file is loaded as a script.
    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\ n" % self.wanted_name)

    # This is called by IDA when it is unloading the plugin.
    def term(self):
        # unhook our plugin hooks
        self._hooks.unhook()
        # unregister our actions & free their resources
        self._del_action_decrypt_bytes()
        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    #--------------------------------------------------------------------------
    # Plugin Hooks
    #--------------------------------------------------------------------------

    # Install plugin hooks into IDA.
    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    # Install Hex-Rrays hooks (when available).
    # NOTE: This is called when the ui_ready_to_run event fires.
    def _init_hexrays_hooks(self):
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hex_callback)

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    def _init_action_decrypt_bytes(self):
        # Register the copy bytes action with IDA.
        
        # Describe the action using python3 copy
        menu_actions = (
            idaapi.action_desc_t(
                ACTION_MENU[0],                             # the action name
                "Open",                                     # the action text
                menu_action_handler_t(ACTION_MENU[0]),      # the action handler
                None,                                       # Optional: action shortcut PLUGIN_HOTKEY
                None,                                       # Optional: tooltip
                31                                          # Copy icon
            ),
            
            idaapi.action_desc_t(
                ACTION_MENU[1],                             # the action name
                "set_var",                                  # the action text
                menu_action_handler_t(ACTION_MENU[1]),      # the action handler
                None,                                       # Optional: action shortcut PLUGIN_HOTKEY
                None,                                       # Optional: tooltip
                201                                         # Copy icon
            ),
        )

        for action in menu_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

    def _del_action_decrypt_bytes(self):
        # Delete the bulk prefix action from IDA.
        for action in self.registered_actions:
            idaapi.unregister_action(action)

# main window of the plugin
class ida_chef_window(idaapi.PluginForm):

    # Called when the widget is created
    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # create an empty list
        self.list = QtWidgets.QListWidget()
        self.list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.list.currentItemChanged.connect(self.print_item)
        
        # item         
        self.list.addItem("WE NEED A HERO")

        # table 
        self.table = QtWidgets.QTableWidget()
        self.table.setRowCount(4)
        self.table.setColumnCount(25)
        self.table.setHorizontalHeaderLabels(["Rule File", "Rename", "Comment", "Pattern"])
        self.table.setItem(0,0, QtWidgets.QTableWidgetItem("Cell (1,1)"))
        self.table.setItem(0,1, QtWidgets.QTableWidgetItem("Cell (1,2)"))
        self.table.setItem(1,0, QtWidgets.QTableWidgetItem("Cell (2,1)"))
        self.table.setItem(1,1, QtWidgets.QTableWidgetItem("Cell (2,2)"))
        self.table.setItem(2,0, QtWidgets.QTableWidgetItem("Cell (3,1)"))
        
        # create a button and connect it's "clicked" signal to our "add_item" slot
        self.genbtn = QtWidgets.QPushButton("Generate Skelton From Current Function (Cursor)")
        self.genbtn.clicked.connect(self.add_item)
        self.addbtn = QtWidgets.QPushButton("Add Rule From Selected Attributes")
        self.addbtn.clicked.connect(self.add_item)
        layout.addWidget(self.table)
        layout.addWidget(self.genbtn)
        layout.addWidget(self.list)
        layout.addWidget(self.addbtn)
        layout.addWidget(self.list)

        # make our created layout the dialogs layout
        self.parent.setLayout(layout)

    def add_item(self):
        self.list.addItem("BRRRRRRRR")
        
    def print_item(self):
        print(self.list.currentItem().text())

    def OnClose(self, form):
        pass
    def Show(self):
        return idaapi.PluginForm.Show(self, 'IDA Chef', options=self.WOPN_PERSIST)

# set the variable name if it's not defined as a bytes, unk, so on ... in IDA
class ida_chef_set_var(idaapi.Form):
    
    # window for user to enter the variable name
    def __init__(self):
            self.invert = False
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""STARTITEM {id:var_name}
                    Set Variable Name
                    Specify the variable name you want.
                    <##Variable Name\::{var_name}>
                    """, {
                            'var_name': F.StringInput(swidth=40),
                        }
            )
    
    # copy the selected bytes that the user mark
    def copy_bytes(self):
        start = idc.read_selection_start()
        end = idc.read_selection_end()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idaapi.get_item_head(ea)
            end = idaapi.get_item_end(ea)
        data = idc.get_bytes(start, end - start).hex()
        return data

# Required plugin entry point for IDAPython Plugins.
def PLUGIN_ENTRY():
    return ida_chef()