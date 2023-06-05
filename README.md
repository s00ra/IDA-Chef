# IDA-Chef
## UNDER DEVELOPMENT
## Introduction
IDA-Chef is an IDA plugin that simulates the functionality of CyberChef within IDA. It provides a convenient way to perform cryptographic operations and decryption within the IDA disassembler environment.



![](https://github.com/s00ra/IDA-Chef/blob/main/project%20desc.png)

## IDEA
```
'''
 ___   ______   _______    _______  __   __  _______  _______ 
|   | |      | |   _   |  |       ||  | |  ||       ||       |
|   | |  _    ||  |_|  |  |       ||  |_|  ||    ___||    ___|
|   | | | |   ||       |  |       ||       ||   |___ |   |___ 
|   | | |_|   ||       |  |      _||       ||    ___||    ___|
|   | |       ||   _   |  |     |_ |   _   ||   |___ |   |    
|___| |______| |__| |__|  |_______||__| |__||_______||___|    
'''
```
-----------
 Features
-----------
     [1] Choose the desired algorithm. Instead of manually copying and pasting values, you can simply type the byte_name. 
         With just a few clicks, the plugin will provide the decrypted text, making the decryption process faster and more efficient.
     
     [2] you can insert your own encryption/decryption file into the program
            - for example if the function take two parameter func(key, ct)
              - it will appear like two text input (number of parameter)
              - hidden text in each input panel with the same variable name passed to parameter
              ---------     ---------
              |  key    |   |   ct    |
               ---------     ---------
                       ----------------------
                      |      result          | (depend on how many values are returned from that func)
                       ----------------------

           you can save that file for feature work in the fun_crypto folder
    
     [3] If you choose AES algorithm as recipe and you set the key, IV values
          you can choose this recipe and set it as Block_1
            right click on the encrypted value and choose option decrypt with Block_1
            it will edit the ida value to the decrypted the value 
            add a comment that was decrypted by Block_1
 
     [4] imagine that IDA doesn't locate a byte_xxxx
         - you can select those bytes 
         - name them as var_1 for example
         - do your operation
         
         - these data can be overwritten
             - if it's a simple vm obfuscation being xored with a specific value for example

-----------
## Setup
Copy the `fun_crypto` folder and `idaChef.py` to your plugins folder in IDA

![](https://github.com/s00ra/IDA-Chef/assets/120357712/f4dbec4e-2587-46b8-bda6-44a8e87abce2)

-----------
## How to use
right click and you will see `IDA Chef` added to your menu
  - you can open the plugin
  - you can set a variable with any names you want
    - mark any thing you want and choose set_var option

<p align="center" width="100%">
    <img src="https://github.com/s00ra/IDA-Chef/assets/120357712/d290110a-4910-4c6b-bb21-194d135231d6"> 
</p>
