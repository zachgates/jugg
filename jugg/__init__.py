__version__ = '1.1.8'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2017 Zach Gates'

__author__ = 'Zach Gates'
__email__ = 'thezachgates@gmail.com'

__all__ = [
    'client',
    'constants',
    'core',
    'security',
    'server',
    'utils',
]

try:
    import os, sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

    for module in __all__:
        __import__('jugg.' + module)

    del os, sys
except NameError:
    pass
