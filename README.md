# RESDecryptor

Tool for extracting secrets stored in RES (One) Automation (Manager)

Internal encryption of secrets in RES is fairly straightforward, using a substitution cipher with a small number of hardcoded keys. This tool helps you decrypt secrets, either extracted from building blocks, from the datastore, or otherwise.

For now the tool deals with secrets stored in __Task__ objects. Secrets from global variables are encrypted in a different manner.

## Example

```python
Python 3.6.0 (default, Jan  2 2017, 17:55:52)
[GCC 4.2.1 Compatible Apple LLVM 8.0.0 (clang-800.0.42.1)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from resdecryptor import *
>>> my_key = cipher_keys["command"]
>>> my_key
'Grail'
>>> my_string = 'All your base are belong to us.'
>>> my_secret = encrypt(my_string, my_key)
>>> my_secret
'00B300CD00D5008C00C000E100D600DB008C00A900D300D400CE008C00A800E400C6008900CE00AC00DE00D000D700D3006700E600D0008900E100BA00A0'
>>> decrypt(my_secret, my_key)
'All your base are belong to us.'
>>>
```

## To Do

I would like to:

- add (bulk) parsing / extraction from building block xml
- complete list of task types / keys
- add support for secrets in global variables