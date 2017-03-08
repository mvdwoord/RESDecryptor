#!/usr/bin/env python
"""RES Decryptor helps with decrypting (or encrypting) secrets stored in RES (One) Automation (Manager)."""
# import builtins
# import 3rd party
# Modify path
# Authorship information
__author__ = "Maarten van der Woord"
__copyright__ = "Copyright 2007, Maarten van der Woord"
__credits__ = ["Maarten van der Woord"]
__license__ = "Unlicense"
__version__ = "0.1"
__maintainer__ = "Maarten van der Woord"
__email__ = "maarten@vanderwoord.nl"
__status__ = "Development"

# Several cipher keys are in use, depending on the type of task the secret is stored in.
# I have listed some, but the list can be extended somewhat.
cipher_keys = {
    "command"   : "Grail",
    "filetask"  : "17FiLeVerSioN1988",
    "deploytask": "77DepLoyComPoNent14",
    "adtask"    : "ActiveDirectory",
    "unknown"   : "Dune2",
    "wfstudio"  : "R3SWFsTuD10",
    "well..."   : "RES=Gold",
    "maitask"   : "Send@Mail",
    "sshtask"   : "SSHCommands",
    "domaintask": "TaskDomain",
    "webservice": "WebService"
}

task_cipher_keys = {
    "DOMAIN"          : {"username": "Install"},
    "COMMAND"         : {"username": "Command"},
    "QFILEVERSION"    : {"username": "17FiLeVerSioN1988"},
    "SERVICE"         : {"username": "TaskService"},
    "SOFTGRID"        : {"username": "SoftGrid"},
    "QSOFTGRID"       : {"username": "SoftGrid"},
    "WISDOMCOMPONENT" : {"username": "77DepLoyComPoNent14"},
    "MSI"             : {"dbuser": "SQLScript"},
    "QEXECUTESQL"     : {"dbuser": "SQLScript"},
    "DOMAINUSERCREATE": {"logondomainaccount": "ManageDA"},
    "MANAGEMAILBOX"   : {"domainusername": "DomUserPass"},
    "QMAILBOX"        : {"domainusername": "DomUserPass"},
    "PWRSHELL"        : {"username": "Command"},
    "ADUSER"          : {"domainusername": "DomUserPass"},
    "VMWARE"          : {"username": "VirtualInfrastructure"},
    "SSH"             : {"username": "SSHCommands"},
    "FILEOPERATIONS"  : {"username": "FileOps"},
    "SMTP"            : {"username": "Send@Mail"},
    "CTXWORKFLOW"     : {"username": "R3SWFsTuD10"},
    "SCCMDISTSOFT"    : {"username": "MicSCCM"},
    "LANDESKDISTSOFT" : {"username": "LANDesk"},
    "WEBSERVICE"      : {"securitycontext": "WebService"},
    "QPUBLAPPS"       : {"username": "CitrixApps"}
}


def hexstring_to_wydelist(s):
    """Takes hexadecimal string representation and breaks it up into a list of wydes.
        This could be factored into hextsinrg_to_intlist function but it is useful standalone
        for exploring and debugging."""
    n = 4
    return list([s[i:i+n] for i in range(0, len(s), n)])


def hexstring_to_intlist(s):
    """Takes hexadecimal string representation and returns a list of numerical values (codepoints)."""
    return list(map((lambda x: int(x, 16)), hexstring_to_wydelist(s)))


def string_to_intlist(s):
    """Takes a normal string and returns a list of numerical values (codepoints)"""
    return [ord(c) for c in s]


def encrypt(s, k):
    """Encrypts string s with key k."""
    encrypted_values = [(ord(c) + ord(k[(i + 1) % len(k)])) for i, c in enumerate(s)]
    return "".join(map((lambda x: format(x, '04X')), encrypted_values))


def decrypt(s, k):
    """Decrypts secret s using key k."""
    encrypted_values = hexstring_to_intlist(s)
    decrypted_values = [(c - ord(k[(i + 1) % len(k)])) for i, c in enumerate(encrypted_values)]
    return "".join(map((lambda x: chr(x)), decrypted_values))


def derive_key(p, c):
    """Derives the cypherkey given a known plain text (p) and cypher text (c)
    It will not return the key as such, but a string with the length of the original plain text.
    This contains a part, all or a repetition of the key, depending on plain text, and key length.
    The string is offset by 1 character with regards to the real key. Example: if the key is 'Command'
    the string looks like 'ommandCommandComm'.. etc."""
    plain_ints = [ord(char) for char in p]
    # print(plain_ints)
    cypher_ints = hexstring_to_intlist(c)
    # print(cypher_ints)
    assert len(cypher_ints) == len(plain_ints), "Plain text and cypher text are different length."
    key_ints = [c - p for p, c in zip(plain_ints, cypher_ints)]
    return "".join(map((lambda x: chr(x)), key_ints))
