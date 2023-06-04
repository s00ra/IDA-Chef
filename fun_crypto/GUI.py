import os

import idc
import ida_bytes
import idautils

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QLineEdit, QCompleter, QPushButton
from PyQt5.QtCore import Qt, QMimeData
from PyQt5.QtGui import QDrag, QPixmap, QCursor

dir_path = os.path.dirname(os.path.abspath(__file__))
pngs_folder = os.path.join(dir_path, "pngs")
encryption_functions = ["To Base64", "Hex"]
all_btns = []

global self_val

# class to enable drag and drop
class Button(QPushButton):
    def __init__(self, title, parent, attr):
        super().__init__(title, parent)
        self.setAcceptDrops(True)
        self.attr = attr
        
    def mouseMoveEvent(self, e):
        if e.buttons() == Qt.LeftButton:
            drag = QDrag(self)
            mime = QMimeData()
            drag.setMimeData(mime)
            pixmap = QPixmap(self.size())
            self.render(pixmap)
            drag.setPixmap(pixmap)
            drag.exec_(Qt.MoveAction)

    def dragEnterEvent(self, e):
        e.accept()

    def dropEvent(self, e):
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.addWidget(QPushButton('1'),0,0)
        self.attr.addLayout(self.gridLayout)
        e.accept()

def ui_setup_windows(self):
    global self_val
    self_val = self

    _translate = QtCore.QCoreApplication.translate
    
    # contain the whole GUI
    self.verticalLayout = QtWidgets.QVBoxLayout()
    self.verticalLayout.setObjectName("verticalLayout")
    
    # the top bar 
        # [operations_text, refresh_btn]
        # [recipe_text, delete_btn]
        # [input_text, process_btn, open_folder_btn, delete_btn]
    self.names_action_btn_H = QtWidgets.QHBoxLayout()
    self.names_action_btn_H.setContentsMargins(0, 5, 0, 5)
    self.names_action_btn_H.setObjectName("names_action_btn_H")
    
    # operations_text
    self.operations_2 = QtWidgets.QLabel()
    self.operations_2.setObjectName("operations_2")
    
    self.names_action_btn_H.addWidget(self.operations_2, 1)
    
    # refresh_btn
    self.Refresh = QtWidgets.QPushButton()
    self.Refresh.setFlat(True)
    self.Refresh.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "refresh.png")))
    self.Refresh.setIconSize(QtCore.QSize(24,24))
    self.Refresh.setObjectName("Refresh")
    
    self.names_action_btn_H.addWidget(self.Refresh, 1)
    
    # recipe_text
    self.Recipe = QtWidgets.QLabel()
    self.Recipe.setObjectName("Recipe")
    
    self.names_action_btn_H.addWidget(self.Recipe, 2)
    
    # delete_btn
    self.recipe_del = QtWidgets.QPushButton()
    self.recipe_del.setFlat(True)
    self.recipe_del.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "delete.png")))
    self.recipe_del.setIconSize(QtCore.QSize(24,24))
    self.recipe_del.setObjectName("recipe_del")
    
    self.names_action_btn_H.addWidget(self.recipe_del, 2)
    
    # input_text (input)
    self.Input = QtWidgets.QLabel()
    self.Input.setObjectName("Input")
    
    self.names_action_btn_H.addWidget(self.Input, 1)

    # process_btn (input)
    self.process_input = QtWidgets.QPushButton()
    self.process_input.setToolTip("Process the input to the desired values")
    self.process_input.setFlat(True)
    self.process_input.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "spinner.png")))
    self.process_input.setIconSize(QtCore.QSize(24,24))

    self.process_input.setObjectName("process_input")

    self.names_action_btn_H.addWidget(self.process_input, 1)
    
    # open_folder_btn (input)
    self.open_file_input = QtWidgets.QPushButton()
    self.open_file_input.setFlat(True)
    self.open_file_input.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "folder.png")))
    self.open_file_input.setIconSize(QtCore.QSize(24,24))
    self.open_file_input.setObjectName("open_file_input")
    
    self.names_action_btn_H.addWidget(self.open_file_input, 1)
    
    # delete_btn (input)
    self.input_del = QtWidgets.QPushButton()
    self.input_del.setFlat(True)
    self.input_del.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "delete.png")))
    self.input_del.setIconSize(QtCore.QSize(24,24))
    self.input_del.setObjectName("input_del")
    
    self.names_action_btn_H.addWidget(self.input_del, 1)
    
    self.verticalLayout.addLayout(self.names_action_btn_H)
    
    # main window
    self.main_layout = QtWidgets.QHBoxLayout()
    self.main_layout.setSizeConstraint(QtWidgets.QLayout.SetNoConstraint)
    self.main_layout.setContentsMargins(0, 0, 0, -1)
    self.main_layout.setSpacing(0)
    self.main_layout.setObjectName("main_layout")
    
    self.verticalLayout_4 = QtWidgets.QVBoxLayout()
    self.verticalLayout_4.setContentsMargins(-1, 0, 0, -1)
    self.verticalLayout_4.setObjectName("verticalLayout_4")
    
    # search box
    self.search_bar_vertical = QtWidgets.QVBoxLayout()
    self.search_bar_vertical.setContentsMargins(0, 5, -1, 20)
    self.search_bar_vertical.setObjectName("search_bar_vertical")
    
    self.search = QLineEdit()
    self.search.setPlaceholderText("Search...")
    self.search.textChanged.connect(search_enc_algorithm_update)
    self.search.setObjectName("search")
    self.search_bar_vertical.addWidget(self.search)
    
    self.verticalLayout_4.addLayout(self.search_bar_vertical)
    
    # contains the whole operations
    self.operations = QtWidgets.QScrollArea()
    self.operations.setEnabled(True)
    self.operations.setLayoutDirection(QtCore.Qt.LeftToRight)
    self.operations.setAutoFillBackground(False)
    self.operations.setWidgetResizable(True)
    self.operations.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
    self.operations.setObjectName("operations")
    
    self.all_operations_scroll = QtWidgets.QWidget()
    self.all_operations_scroll.setGeometry(QtCore.QRect(0, 0, 343, 804))
    self.all_operations_scroll.setObjectName("all_operations_scroll")
    self.all_operations_scroll.setAcceptDrops(True)

    self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.all_operations_scroll)
    self.verticalLayout_2.setAlignment(Qt.AlignTop)
    self.verticalLayout_2.setObjectName("verticalLayout_2")

    self.completer = QCompleter(encryption_functions)
    self.completer.setCaseSensitivity(Qt.CaseInsensitive)
    self.search.setCompleter(self.completer)

    self.operations.setWidget(self.all_operations_scroll)
    self.verticalLayout_4.addWidget(self.operations)
    self.main_layout.addLayout(self.verticalLayout_4, 2)
    
    self.recipe = QtWidgets.QScrollArea()
    self.recipe.setWidgetResizable(True)
    self.recipe.setObjectName("recipe")

    self.scrollAreaWidgetContents = QtWidgets.QWidget()
    self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 363, 709))
    self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
    self.scrollAreaWidgetContents.setAcceptDrops(True)

    self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)
    self.verticalLayout_3.setAlignment(Qt.AlignTop)
    self.verticalLayout_3.setContentsMargins(0, 0, -1, -1)
    self.verticalLayout_3.setObjectName("verticalLayout_3")
    
    self.recipe.setWidget(self.scrollAreaWidgetContents)
    self.main_layout.addWidget(self.recipe, 4)
    
    # it's png for the cursor
    pixmap = QPixmap(os.path.join(pngs_folder, "grab.png"))
    # btns of the operations
    for i, l in enumerate(encryption_functions):
        self.btn = Button(l, self.all_operations_scroll, self.verticalLayout_3)


        self.btn.setCursor(QCursor(pixmap, 0, 0))
        self.btn.setFlat(True)
        self.btn.setStyleSheet(
            "QPushButton"
            "{"
                "color: #002B5B;"
                "background-color: #cce4ff;"
                "padding-left: 20px;"
                "padding-top: 9px;"
                "padding-bottom: 10px;"
                "border: 2px solid #cce4ff;"
                "border-radius: 5px;"
                "font-size: 15px;"
                "font-weight: bold;"
                "text-align: left;"
            "}"
        )

        all_btns.append(self.btn)
        self.btn.setObjectName(l)
        self.btn.setText(_translate("main_window", l))

        self.verticalLayout_2.addWidget(self.btn)

    self.input_output = QtWidgets.QVBoxLayout()
    self.input_output.setContentsMargins(0, -1, 0, -1)
    self.input_output.setObjectName("input_output")
    
    # input box
    self.input = QtWidgets.QPlainTextEdit()
    self.input.setObjectName("input")
    
    self.input_output.addWidget(self.input)
    
    # output that contains
        # [output_text, save_to_file_btn, copy_btn, replace_input_with_output_btn]
    self.output_actions = QtWidgets.QHBoxLayout()
    self.output_actions.setContentsMargins(-1, 5, -1, 5)
    self.output_actions.setObjectName("output_actions")
    
    self.output_2 = QtWidgets.QLabel()
    self.output_2.setObjectName("output_2")
    
    self.output_actions.addWidget(self.output_2, 1)
    
    self.save_output_to_file = QtWidgets.QPushButton()
    self.save_output_to_file.setToolTip("Save output to file")
    self.save_output_to_file.setFlat(True)
    self.save_output_to_file.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "save.png")))
    self.save_output_to_file.setIconSize(QtCore.QSize(24,24))
    self.save_output_to_file.setObjectName("save_output_to_file")

    self.output_actions.addWidget(self.save_output_to_file, 1)

    self.copy_output = QtWidgets.QPushButton()
    self.copy_output.setToolTip("Copy raw output to the clipboard")
    self.copy_output.setFlat(True)
    self.copy_output.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "copy.png")))
    self.copy_output.setIconSize(QtCore.QSize(24,24))
    self.copy_output.setObjectName("copy_output")
    
    self.output_actions.addWidget(self.copy_output, 1)
    
    self.replace_input_with_output = QtWidgets.QPushButton()
    self.replace_input_with_output.setToolTip("Replace input with output")
    self.replace_input_with_output.setFlat(True)
    self.replace_input_with_output.setIcon(QtGui.QIcon(os.path.join(pngs_folder, "move_up.png")))
    self.replace_input_with_output.setIconSize(QtCore.QSize(24,24))
    self.replace_input_with_output.setObjectName("replace_input_with_output")
    
    self.output_actions.addWidget(self.replace_input_with_output, 1)
    self.input_output.addLayout(self.output_actions)
    
    self.output = QtWidgets.QPlainTextEdit()
    self.output.setReadOnly(True)
    self.output.setObjectName("output")
    
    self.input_output.addWidget(self.output)
    self.main_layout.addLayout(self.input_output, 4)
    self.verticalLayout.addLayout(self.main_layout)
    
    # connect btns
    # TODO
    self.process_input.clicked.connect(process_the_input)

    self.operations_2.setText(_translate("main_window", "Operations"))
    self.Recipe.setText(_translate("main_window", "Recipe"))
    self.Input.setText(_translate("main_window", "Input"))
    self.output_2.setText(_translate("main_window", "output"))
    
    self.parnet.setLayout(self.verticalLayout)

# search box of the recipe
def search_enc_algorithm_update(text):
    for widget in all_btns:
        if text.lower() in widget.objectName().lower():
            widget.show()
        else:
            widget.hide()

# type the name of the .rdata, .data variable
    # and it will load the all value
def export_data_values(data_name):
    # Get the address of the data variable
    data_addr = idc.get_name_ea_simple(data_name)
    if data_addr == idc.BADADDR:
        print(f"Error: Couldn't find the address of {data_name}")
        return
    data_size = idc.next_head(data_addr) - data_addr - 1
    data_val = idc.get_bytes(data_addr, data_size)
    return data_val

# process the text in the input box and set the text of the output
    # for example if the user enter byte_xxxx it will pass the value of byte_xxxx
    # if user enter "+" it will concatenate the values and apply the recipe on the whole input
    # if user enter "," it will separate the values and apply the recipe on the input separately
def process_the_input():
    input_string = self_val.input.toPlainText()
    bytes_ida_val = export_data_values(input_string)
    self_val.output.appendPlainText(bytes_ida_val.hex())