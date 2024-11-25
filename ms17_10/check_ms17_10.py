from .mysmb import MYSMB

'''
Script for
- check target if MS17-010 is patched or not.
- find accessible named pipe
'''

def check_ms17_10(target_ip, port, username, password):
    connection = MYSMB(target_ip, int(port))
    connection.login_or_fail(username, password)

    tid = connection.tree_connect_andx('\\\\' + target_ip + '\\' + 'IPC$')
    connection.set_default_tid(tid)

    result = connection.check_ms17_010()
    
    connection.disconnect_tree(tid)
    connection.logoff()
    connection.get_socket().close()

    
    return result
