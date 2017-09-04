__version__ = '1.0.2'
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

for module in __all__:
    __import__('imposter.%s' % module)
