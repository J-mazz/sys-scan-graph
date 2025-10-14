#    .________      ._____.___ .______  .______ .______ .___ .______  .___
#    :____.   \     :         |:      \ \____  |\____  |: __|:      \ : __|
#     __|  :/ |     |   \  /  ||   .   |/  ____|/  ____|| : ||       || : |
#    |     :  |     |   |\/   ||   :   |\      |\      ||   ||   |   ||   |
#     \__. __/      |___| |   ||___|   | \__:__| \__:__||   ||___|   ||   |
#        :/               |___|    |___|    :       :   |___|    |___||___|
#        :                                  •       •                 
#                                                                          
#
#    2925
#    __init__.py

# ==============================================================================
# Agent package init

import subprocess
import sys

def _check_sys_scan():
    """Check if sys-scan-graph core is installed and available."""
    try:
        # Check if 'sys-scan-graph' is in the system's PATH
        subprocess.run(["which", "sys-scan-graph"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(
            "Error: 'sys-scan-graph' core not found.\n"
            "Please install the core package first by running:\n"
            "sudo apt install sys-scan-graph",
            file=sys.stderr
        )
        sys.exit(1)

# Perform the check when the module is imported
_check_sys_scan()
